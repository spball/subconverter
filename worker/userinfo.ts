import { Config, expandEntries, Loader } from './config';
import { Node } from './nodes';
import { regex } from './util';

function bytes(text: string): number {
  const m = /^\s*([\d.]+)\s*([kmgtpe]?)(?:i?b)?\s*$/i.exec(text);
  return m ? Number(m[1]) * 1024 ** Math.max(0, ' kmgtpe'.indexOf(m[2].toLowerCase())) : NaN;
}
export async function extractUserInfo(nodes: Node[], cfg: Config, load: Loader): Promise<string> {
  const streamRules = await expandEntries(cfg.userinfo.stream_rule, load, 'userinfo');
  const timeRules = await expandEntries(cfg.userinfo.time_rule, load, 'userinfo');
  let total = NaN, used = NaN, left = NaN, expire = NaN;
  for (const n of nodes) {
    for (const entry of streamRules) {
      const at = entry.lastIndexOf('|'); if (at < 0) continue;
      const r = regex(entry.slice(0, at)); if (!r.test(n.name)) continue;
      const values = new URLSearchParams(n.name.replace(r, entry.slice(at + 1)));
      if (values.has('total')) total = bytes(values.get('total')!);
      if (values.has('used')) used = bytes(values.get('used')!);
      if (values.has('left')) left = bytes(values.get('left')!);
      break;
    }
    for (const entry of timeRules) {
      const at = entry.lastIndexOf('|'); if (at < 0) continue;
      const r = regex(entry.slice(0, at)); if (!r.test(n.name)) continue;
      const value = n.name.replace(r, entry.slice(at + 1)), relative = /^left=([\d.]+)d$/.exec(value);
      if (relative) expire = Math.floor(Date.now() / 1000 + Number(relative[1]) * 86400);
      else { const parts = value.split(':').map(Number); if (parts.length === 6 && parts.every(Number.isFinite)) expire = Date.UTC(parts[0], parts[1] - 1, parts[2], parts[3], parts[4], parts[5]) / 1000; }
      break;
    }
  }
  if (!Number.isFinite(used) && Number.isFinite(total) && Number.isFinite(left)) used = total - left;
  if (!Number.isFinite(total) && Number.isFinite(used) && Number.isFinite(left)) total = used + left;
  if (!Number.isFinite(total) && !Number.isFinite(expire)) return '';
  return `upload=0; download=${Math.max(0, Math.floor(used || 0))}; total=${Math.max(0, Math.floor(total || 0))}${Number.isFinite(expire) ? '; expire=' + Math.floor(expire) : ''}`;
}
