import { Config } from './config';
import { Snapshot } from './state';
import { bool, digest, HttpError, integer, readBounded, safePath } from './util';

export interface Resource { text: string; headers: Headers; }
export class Resources {
  private requests = 0;
  private totalBytes = 0;
  private memo = new Map<string, Promise<Resource>>();
  constructor(private env: Env, private ctx: ExecutionContext, private state: Snapshot, public config?: Config) {}
  async local(path: string, scope = ''): Promise<string> {
    path = safePath(path, scope);
    return (await this.read(path, 'config')).text;
  }
  load = async (path: string, kind: 'config' | 'ruleset' | 'subscription' = 'config'): Promise<string> => (await this.read(path, kind)).text;
  async read(path: string, kind: 'config' | 'ruleset' | 'subscription'): Promise<Resource> {
    const key = kind + ':' + path;
    let task = this.memo.get(key);
    if (!task) { task = this.fetchResource(path, kind); this.memo.set(key, task); }
    return task;
  }
  private async fetchResource(path: string, kind: 'config' | 'ruleset' | 'subscription'): Promise<Resource> {
    const remote = /^https?:\/\//i.test(path);
    if (!remote) path = safePath(path);
    const adv = this.config?.advanced ?? {};
    const ttl = integer(adv['cache_' + kind], kind === 'ruleset' ? 21600 : kind === 'config' ? 300 : 60, 0, 86400 * 30);
    const enabled = remote && bool(adv.enable_cache, true) && ttl > 0 && !(kind === 'ruleset' && bool(this.config?.rulesets.update_ruleset_on_request));
    const cacheKey = new Request('https://subconverter-cache.invalid/' + await digest(JSON.stringify([path, kind, this.state.version, this.state.epoch, kind === 'ruleset' ? this.state.rulesEpoch : 0])));
    if (enabled) {
      const hit = await caches.default.match(cacheKey);
      if (hit) return { text: await this.consume(hit), headers: hit.headers };
    }
    let url = remote ? new URL(path) : new URL('/' + path.split('/').map(encodeURIComponent).join('/'), 'https://assets.invalid');
    let response: Response | undefined;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    try {
      for (let i = 0; i <= 5; i++) {
        if (++this.requests > 40) throw new HttpError(422, 'Resource request budget exceeded');
        if (remote && (!['http:', 'https:'].includes(url.protocol) || url.username || url.password)) throw new HttpError(400, 'Invalid resource URL');
        response = remote ? await fetch(url.toString(), { redirect: 'manual', signal: controller.signal, headers: { 'User-Agent': 'subconverter-workers/1.0' } }) : await this.env.ASSETS.fetch(url.toString());
        if (remote && [301, 302, 303, 307, 308].includes(response.status)) {
          const location = response.headers.get('location'); await response.body?.cancel();
          if (!location || i === 5) throw new HttpError(502, 'Too many or invalid redirects');
          url = new URL(location, url); continue;
        }
        break;
      }
      if (!response?.ok) { await response?.body?.cancel(); throw new HttpError(remote ? 502 : 404, remote ? 'Upstream resource unavailable' : 'Not found'); }
      const text = await this.consume(response);
      const headers = new Headers(response.headers);
      if (enabled) {
        const cacheHeaders = new Headers({ 'Cache-Control': `max-age=${ttl}` });
        for (const name of ['Subscription-UserInfo', 'profile-web-page-url', 'content-type']) if (headers.has(name)) cacheHeaders.set(name, headers.get(name)!);
        this.ctx.waitUntil(caches.default.put(cacheKey, new Response(text, { headers: cacheHeaders })).catch(() => undefined));
      }
      return { text, headers };
    } catch (e) {
      if (e instanceof HttpError) throw e;
      throw new HttpError(controller.signal.aborted ? 504 : 502, controller.signal.aborted ? 'Resource request timed out' : 'Resource request failed');
    } finally { clearTimeout(timeout); }
  }
  private async consume(response: Response): Promise<string> {
    const configured = integer(this.config?.advanced.max_allowed_download_size, 0);
    const text = await readBounded(response, configured > 0 ? Math.min(configured, 2 * 1024 * 1024) : 2 * 1024 * 1024);
    this.totalBytes += new TextEncoder().encode(text).byteLength;
    if (this.totalBytes > 8 * 1024 * 1024) throw new HttpError(413, 'Total resource size exceeded');
    return text;
  }
}
