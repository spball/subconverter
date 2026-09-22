import { ConfigStore } from './state';
import { Config, expandEntries, listValue, parseConfig, parseIni } from './config';
import { convert, templateData } from './convert';
import { Resources } from './resources';
import { readRules, rulesetOutput } from './rules';
import { renderTemplate } from './template';
import { b64decode, bool, HttpError, integer, readBounded, record, safePath, str, tokenEquals } from './util';

export { ConfigStore };
const methods: Record<string, string[]> = {
  '/version': ['GET'], '/sub': ['GET', 'HEAD'], '/sub2clashr': ['GET'], '/surge2clash': ['GET'],
  '/getruleset': ['GET'], '/getprofile': ['GET'], '/render': ['GET'], '/readconf': ['GET'],
  '/updateconf': ['POST'], '/refreshrules': ['GET'], '/flushcache': ['GET'], '/get': ['GET'], '/getlocal': ['GET']
};
async function serve(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url); let path = url.pathname, params = url.searchParams;
  if (path === '/version') return request.method === 'GET' ? text('subconverter workers 1.0.0 backend\n') : text('Method Not Allowed', 405, { Allow: 'GET' });
  const store = env.CONFIG.getByName('global'); const state = await store.snapshot();
  const resources = new Resources(env, ctx, state);
  const cfg = parseConfig(state.text ?? await resources.local(env.DEFAULT_CONFIG)); resources.config = cfg;
  const alias = str(cfg.aliases[path]);
  if (alias) {
    const to = new URL(alias, url.origin);
    for (const [k, v] of params) to.searchParams.append(k, v);
    return new Response(null, { status: 302, headers: { Location: to.origin === url.origin ? to.pathname + to.search : to.toString() } });
  }
  if (!methods[path] || (path === '/get' || path === '/getlocal') && bool(cfg.common.api_mode, true)) throw new HttpError(404, 'Not found');
  if (!methods[path].includes(request.method)) return text('Method Not Allowed', 405, { Allow: methods[path].join(', ') });
  const secret = env.ACCESS_TOKEN || str(cfg.common.api_access_token);
  const token = params.get('token') ?? request.headers.get('Authorization')?.replace(/^Bearer /i, '') ?? '';
  const admin = await tokenEquals(token, secret), authorized = admin || !bool(cfg.common.api_mode, true);
  if (['/readconf', '/updateconf', '/refreshrules', '/flushcache'].includes(path) && !admin) throw new HttpError(403, 'Forbidden\n');
  if (path === '/updateconf') {
    if (!['direct', 'form'].includes(params.get('type') ?? '')) throw new HttpError(501, 'Not Implemented\n');
    const body = await readBounded(request, 512 * 1024); const candidate = parseConfig(body);
    await validateConfigResources(candidate, resources);
    await store.update(body); return text('done\n');
  }
  if (path === '/readconf') {
    const body = state.text ?? await resources.local(env.DEFAULT_CONFIG); const candidate = parseConfig(body);
    await validateConfigResources(candidate, resources); await store.update(body); return text('done\n');
  }
  if (path === '/flushcache') { await store.bump('epoch'); return text('done'); }
  if (path === '/refreshrules') {
    await store.bump('rulesEpoch'); const fresh = new Resources(env, ctx, await store.snapshot(), cfg);
    const entries = await expandEntries(listValue(cfg.rulesets, 'rulesets', 'ruleset'), fresh.load, 'ruleset');
    for (const entry of entries) { const p = entry.slice(entry.indexOf(',') + 1); if (p && !p.startsWith('[]')) await readRules(p.split(',')[0], fresh.load); }
    return text('done\n');
  }
  if (path === '/get') {
    const link = params.get('url') ?? ''; if (!/^https?:\/\//.test(link)) throw new HttpError(400, 'Invalid URL');
    return text(await resources.load(link));
  }
  if (path === '/getlocal') return text(await resources.local(params.get('path') ?? ''));
  if (path === '/render') {
    const resource = params.get('path') ?? ''; const scope = str(cfg.template.template_path);
    return text(await renderTemplate(await resources.local(resource, scope), templateData(cfg, params), resources.load, scope, str(cfg.managed_config.managed_config_prefix) || url.origin));
  }
  if (path === '/getruleset') {
    const type = integer(params.get('type'), 0, 1, 6), pathList = b64decode(params.get('url') ?? ''), group = params.has('group') ? b64decode(params.get('group')!) : '';
    if (!pathList || type === 2 && !group) throw new HttpError(400, 'Invalid request!');
    const rules: string[] = []; for (const p of pathList.split('|')) rules.push(...await readRules(p, resources.load));
    if (rules.length > 20000) throw new HttpError(413, 'Rule limit exceeded');
    return text(rulesetOutput(rules, type, group));
  }
  if (path === '/sub2clashr' || path === '/surge2clash') {
    const key = path === '/sub2clashr' ? 'sublink' : 'link', link = params.get(key);
    if (!link) throw new HttpError(400, 'Invalid request!');
    if (link === key) throw new HttpError(400, 'Please insert your subscription link instead of clicking the default link.');
    params = new URLSearchParams(params); params.set('url', link); params.set('target', path === '/sub2clashr' ? 'clashr' : 'clash');
  }
  let profileAuthorized = authorized;
  if (path === '/getprofile') {
    const names = (params.get('name') ?? '').split('|').filter(Boolean);
    if (!token || !names.length) throw new HttpError(403, 'Forbidden');
    const first = parseIni(await resources.local(safePath(names[0]))).Profile;
    if (!first || !Object.keys(first).length) throw new HttpError(500, 'Broken profile!');
    if (names.length === 1 && first.profile_token?.[0]) { if (!await tokenEquals(token, first.profile_token[0])) throw new HttpError(403, 'Forbidden'); }
    else if (!admin) throw new HttpError(403, 'Forbidden');
    const combined = new URLSearchParams(); for (const [k, v] of Object.entries(first)) if (k !== 'profile_token') combined.set(k, v[0]);
    for (const name of names.slice(1)) {
      try { const next = parseIni(await resources.local(safePath(name))).Profile; if (next?.url?.[0]) combined.set('url', (combined.get('url') ?? '') + '|' + next.url[0]); }
      catch (e) { if (!(e instanceof HttpError) || e.status !== 404) throw e; }
    }
    for (const [k, v] of params) if (!combined.has(k)) combined.set(k, v);
    params = combined; profileAuthorized = true;
  }
  const result = await convert(request, cfg, resources, profileAuthorized, params, path === '/surge2clash', path === '/getprofile' ? request.url : undefined);
  if (bool(params.get('upload')) && request.method !== 'HEAD') {
    if (!admin) throw new HttpError(403, 'Gist upload requires administrator token');
    if (!env.GIST_TOKEN) throw new HttpError(422, 'GIST_TOKEN is not configured');
    const name = params.get('upload_path') || result.target, id = state.gistId;
    const response = await fetch('https://api.github.com/gists' + (id ? '/' + encodeURIComponent(id) : ''), {
      method: id ? 'PATCH' : 'POST', headers: { Authorization: `Bearer ${env.GIST_TOKEN}`, 'User-Agent': 'subconverter-workers', 'Content-Type': 'application/json', Accept: 'application/vnd.github+json' },
      body: JSON.stringify({ ...(id ? {} : { description: 'subconverter', public: false }), files: { [name]: { content: result.body } } }), signal: AbortSignal.timeout(15000)
    });
    if (!response.ok) { await response.body?.cancel(); throw new HttpError(502, 'Gist upload failed'); }
    const info = record(JSON.parse(await readBounded(response))); if (!info.id) throw new HttpError(502, 'Invalid Gist response');
    await store.saveGist(str(info.id));
  }
  return text(result.body, 200, result.headers);
}
async function validateConfigResources(cfg: Config, resources: Resources): Promise<void> {
  await expandEntries(cfg.proxy_groups.custom_proxy_group, resources.load, 'group');
  await expandEntries(listValue(cfg.rulesets, 'rulesets', 'ruleset'), resources.load, 'ruleset');
  await expandEntries(cfg.node_pref.rename_node, resources.load, 'rename');
  await expandEntries(listValue(cfg.emojis, 'rules', 'rule'), resources.load, 'emoji');
}
function text(body: string, status = 200, headers: HeadersInit = {}): Response {
  const h = new Headers(headers); h.set('Content-Type', 'text/plain;charset=utf-8'); return new Response(body, { status, headers: h });
}
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    let response: Response;
    try {
      if (request.method === 'OPTIONS') response = new Response(null, { status: 204, headers: { 'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' } });
      else response = await serve(request, env, ctx);
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      response = text(e instanceof HttpError ? e.message : 'Internal conversion error', status);
      if (status >= 500) console.error(JSON.stringify({ event: 'request_failed', status }));
    }
    response.headers.set('Access-Control-Allow-Origin', '*');
    response.headers.set('Access-Control-Expose-Headers', 'Subscription-UserInfo, Content-Disposition, profile-update-interval, profile-web-page-url, X-Subconverter-Skipped-Nodes');
    response.headers.set('Cache-Control', 'no-store');
    response.headers.set('X-Content-Type-Options', 'nosniff');
    if (request.method === 'HEAD') { await response.body?.cancel(); return new Response(null, { status: response.status, headers: response.headers }); }
    return response;
  }
} satisfies ExportedHandler<Env>;
