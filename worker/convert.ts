import { array, b64decode, b64encode, bool, Dict, HttpError, integer, lines, record, regex, safePath, setPath, splitOnce, str } from './util';
import { Config, customConfig, expandEntries, listValue, parseConfig } from './config';
import { Node, parseLink, Parsed, parseSubscription } from './nodes';
import { compatible, exportConfig, simpleTargets, Target, targets } from './export';
import { buildRules } from './rules';
import { Resources } from './resources';
import { renderTemplate } from './template';
import { extractUserInfo } from './userinfo';

export function autoTarget(ua: string): { target: string; version?: number; newFields?: boolean } {
  if (/^ClashForAndroid\/.*R/.test(ua)) return { target: 'clashr', newFields: false };
  if (/^(Clash|clash-verge|mihomo)/i.test(ua)) return { target: 'clash', newFields: true };
  for (const [pattern, target] of [[/^Quantumult(?:%20| )X/, 'quanx'], [/^Quantumult/, 'quan'], [/^Loon/, 'loon'], [/^Surfboard/, 'surfboard'], [/^Surge/, 'surge'], [/^(Kitsunebi|Qv2ray|V2rayU|V2RayX)/, 'v2ray'], [/^(Pharos|Potatso|Shadowrocket)/, 'mixed'], [/^Trojan-Qt5/, 'trojan'], [/^sing-box/i, 'singbox']] as const) {
    if (pattern.test(ua)) {
      if (target === 'surge') { const version = Number(/\/(\d+)/.exec(ua)?.[1] ?? 0), mac = ua.includes('x86'); return { target, version: version >= (mac ? 906 : 1419) ? 4 : version >= (mac ? 368 : 900) ? 3 : 2 }; }
      return { target };
    }
  }
  return { target: 'auto' };
}
export function templateData(cfg: Config, params: URLSearchParams, local: Dict = {}): Dict {
  const data: Dict = { global: {}, request: {}, local };
  const request = record(data.request);
  for (const [k, v] of params) if (k !== 'token' && v) setPath(request, k, v);
  const filtered = new URLSearchParams(params); filtered.delete('token'); request._args = filtered.toString();
  const globals = cfg.template.globals ?? cfg.template.global;
  if (Array.isArray(globals)) for (const v of globals) { const p = record(v); if (p.key) setPath(record(data.global), str(p.key), str(p.value)); }
  else for (const [k, v] of Object.entries(record(globals))) setPath(record(data.global), k, str(v));
  for (const [k, v] of Object.entries(cfg.template)) if (!['globals', 'global', 'locals', 'template_path'].includes(k)) setPath(record(data.global), k, str(v));
  record(data.global).managed_config_prefix = str(cfg.managed_config.managed_config_prefix);
  for (const v of array(cfg.template.locals)) { const p = record(v); if (p.key) setPath(local, str(p.key), str(p.value)); }
  return data;
}
function matches(n: Node, pattern: string): boolean {
  if (pattern.startsWith('!!GROUPID=')) {
    const [ids, rest] = splitOnce(pattern.slice(10), '!!');
    const accepted = ids.split(',').some(s => { const m = /^(-?\d+)(?:-(-?\d+))?$/.exec(s); return !!m && n.source >= Number(m[1]) && n.source <= Number(m[2] ?? m[1]); });
    return accepted && (!rest || regex(rest).test(n.name));
  }
  if (pattern.startsWith('!!GROUP=')) { const [group, rest] = splitOnce(pattern.slice(8), '!!'); return regex(group).test(n.group) && (!rest || regex(rest).test(n.name)); }
  if (pattern.startsWith('!!')) throw new HttpError(422, 'Unsupported group selector');
  return regex(pattern).test(n.name);
}
export function makeGroups(entries: string[], nodes: Node[], fallback: Dict[] = []): Dict[] {
  if (!entries.length) return fallback.length ? fallback : [{ name: 'Proxy', type: 'select', proxies: [...nodes.map(n => n.name), 'DIRECT'] }];
  const groups: Dict[] = [];
  for (const entry of entries) {
    const structured = entry.startsWith('@json:') ? record(JSON.parse(entry.slice(6))) : undefined;
    const source = structured ? [str(structured.name), str(structured.type, 'select'), ...array(structured.rule).map(v => str(v)), ...(structured.url ? [str(structured.url), `${str(structured.interval, '300')},${str(structured.timeout)},${str(structured.tolerance)}`] : [])] : entry.split('`');
    const [name, type, ...patterns] = source;
    if (!name || !['select', 'url-test', 'fallback', 'load-balance', 'ssid', 'relay', 'smart'].includes(type)) throw new HttpError(400, 'Invalid proxy group');
    if (type === 'ssid') throw new HttpError(422, 'SSID group output is not supported');
    const group: Dict = { name, type, ...record(structured?.extra) }, members: string[] = [];
    if (structured) for (const key of ['use', 'strategy', 'lazy', 'disable-udp', 'persistent', 'evaluate-before-use']) if (structured[key] !== undefined) group[key] = structured[key];
    if (['url-test', 'fallback', 'load-balance', 'smart'].includes(type)) {
      const timings = patterns.pop()?.split(',') ?? [], url = patterns.pop();
      if (!url || !/^https?:\/\//.test(url)) throw new HttpError(400, 'Missing group test URL');
      group.url = url; group.interval = integer(timings[0], 300); if (timings[1]) group.timeout = integer(timings[1], 5); if (timings[2]) group.tolerance = integer(timings[2], 0);
    }
    for (const p of patterns) {
      if (p.startsWith('[]')) members.push(p.slice(2));
      else if (p.startsWith('!!PROVIDER=')) group.use = [...array(group.use), ...p.slice(11).split(',').filter(Boolean)];
      else members.push(...nodes.filter(n => matches(n, p)).map(n => n.name));
    }
    if (members.length || !array(group.use).length) group.proxies = [...new Set(members.length ? members : ['DIRECT'])];
    groups.push(group);
  }
  const known = new Set([...nodes.map(n => n.name), ...groups.map(g => str(g.name)), 'DIRECT', 'REJECT', 'REJECT-DROP']);
  for (const g of groups) for (const member of array(g.proxies)) if (!known.has(str(member))) throw new HttpError(400, 'Proxy group references unknown member');
  const byName = new Map(groups.map(g => [str(g.name), g]));
  function visit(name: string, stack: string[]): void { if (stack.includes(name)) throw new HttpError(400, 'Cyclic proxy groups'); if (stack.length > 32) throw new HttpError(400, 'Proxy group nesting exceeded'); const g = byName.get(name); if (g) for (const m of array(g.proxies)) if (byName.has(str(m))) visit(str(m), [...stack, name]); }
  groups.forEach(g => visit(str(g.name), [])); return groups;
}
export interface Conversion { body: string; headers: Headers; target: Target; }
export async function convert(request: Request, cfg: Config, resources: Resources, authorized: boolean, params = new URL(request.url).searchParams, preserveSource = false, profileUrl?: string): Promise<Conversion> {
  params = new URLSearchParams(params);
  for (const k of ['filter_script', 'sort_script']) if (params.has(k) && params.get(k) !== 'false') throw new HttpError(422, 'Custom JavaScript execution is not supported');
  let target = params.get('target') ?? '', version = integer(params.get('ver'), 3, 2, 5), newFields = bool(params.get('new_name'), bool(cfg.node_pref.clash_use_new_field_name, true));
  if (target === 'auto') { const match = autoTarget(request.headers.get('User-Agent') ?? ''); target = match.target; version = match.version ?? version; newFields = match.newFields ?? newFields; }
  if (!targets.includes(target as Target)) throw new HttpError(400, 'Invalid target!');
  params.set('target', target); params.set('ver', String(version));
  const simple = simpleTargets.has(target), list = bool(params.get('list'));
  const external = params.get('config') ?? str(cfg.common.default_external_config);
  if (external && !simple) {
    const externalConfig = parseConfig(await resources.load(external));
    for (const [k, v] of Object.entries(externalConfig.custom ?? {})) if (k.endsWith('_rule_base') && !/^https?:\/\//.test(str(v))) safePath(str(v), str(cfg.common.base_path, 'base'));
    cfg = customConfig(cfg, externalConfig);
    resources.config = cfg;
  }
  const input = params.get('url') || (authorized ? array(cfg.common.default_url).map(v => str(v)).join('|') : '');
  const inserted = bool(params.get('insert'), bool(cfg.common.enable_insert, true)) ? array(cfg.common.insert_url).map(v => str(v)).join('|') : '';
  const urls = input.split('|').filter(Boolean), additions = inserted.split('|').filter(Boolean);
  const items = bool(params.get('prepend'), bool(cfg.common.prepend_insert_url, true)) ? [...additions.map(url => ({ url, inserted: true })), ...urls.map(url => ({ url, inserted: false }))] : [...urls.map(url => ({ url, inserted: false })), ...additions.map(url => ({ url, inserted: true }))];
  if (!items.length) throw new HttpError(400, 'Invalid request!');
  if (items.length > 20) throw new HttpError(422, 'Subscription source limit exceeded (20)');
  const headers = new Headers(), all: Node[] = []; let sourceData: Parsed | undefined, sourceIndex = 0;
  for (const item of items) {
    try {
      let url = item.url; if (url.startsWith('surge:///install-config')) url = new URL(url).searchParams.get('url') ?? '';
      const source = item.inserted ? -1 : sourceIndex++;
      let parsed: Parsed;
      if (url.startsWith('ssd://')) parsed = parseSubscription(url, source);
      else if (/^[a-z0-9-]+:\/\//i.test(url) && !/^https?:\/\//i.test(url) || /^https:\/\/t\.me\/(socks|http)/.test(url) || /^https?:\/\/[^/]*@/.test(url)) parsed = { nodes: [parseLink(url, source)], groups: [], rules: [] };
      else {
        if (url.startsWith('script:')) throw new HttpError(422, 'Script subscriptions are not supported');
        if (!/^https?:\/\//i.test(url) && !authorized) throw new HttpError(403, 'Forbidden');
        const resource = await resources.read(url, 'subscription'); parsed = parseSubscription(resource.text, source);
        for (const name of ['Subscription-UserInfo', 'profile-web-page-url']) if (!headers.has(name) && resource.headers.has(name)) headers.set(name, resource.headers.get(name)!);
      }
      sourceData ??= parsed; all.push(...parsed.nodes);
    } catch (e) { if (!bool(cfg.advanced.skip_failed_links) || e instanceof HttpError && [403, 413, 422].includes(e.status)) throw e; }
  }
  if (all.length > 2000) throw new HttpError(413, 'Node limit exceeded (2000)');
  if (!headers.has('Subscription-UserInfo')) { const info = await extractUserInfo(all, cfg, resources.load); if (info) headers.set('Subscription-UserInfo', info); }
  const includes = params.has('include') ? [params.get('include')!] : array(cfg.common.include_remarks).map(v => str(v));
  const excludes = params.has('exclude') ? [params.get('exclude')!] : array(cfg.common.exclude_remarks).map(v => str(v));
  const includeRegex = includes.filter(Boolean).map(p => regex(p)), excludeRegex = excludes.filter(Boolean).map(p => regex(p));
  let nodes = all.filter(n => (!includeRegex.length || includeRegex.some(r => r.test(n.name))) && !excludeRegex.some(r => r.test(n.name)));
  const renames = params.has('rename') ? params.get('rename')!.split('`') : await expandEntries(cfg.node_pref.rename_node, resources.load, 'rename');
  const emojiRules = await expandEntries(listValue(cfg.emojis, 'rules', 'rule'), resources.load, 'emoji');
  for (const n of nodes) {
    if (bool(params.get('remove_emoji'), bool(cfg.emojis.remove_old_emoji))) n.name = n.name.replace(/^(?:[\p{Extended_Pictographic}\p{Regional_Indicator}\uFE0F\u200D]|\s)+/u, '');
    for (const entry of renames) { const at = entry.lastIndexOf('@'); if (at < 0) throw new HttpError(400, 'Invalid rename rule'); if (matches(n, entry.slice(0, at))) n.name = n.name.replace(regex(entry.slice(0, at), true), entry.slice(at + 1)); }
    if (bool(params.get('add_emoji') ?? params.get('emoji'), bool(cfg.emojis.add_emoji))) for (const e of emojiRules) { const at = e.lastIndexOf(','); if (at > 0 && regex(e.slice(0, at)).test(n.name)) { n.name = e.slice(at + 1) + ' ' + n.name; break; } }
    if (bool(params.get('append_type'), bool(cfg.common.append_proxy_type))) n.name = `[${n.type.toUpperCase()}] ${n.name}`;
    if (params.has('group')) n.group = params.get('group')!;
    for (const [param, setting, prop] of [['udp', 'udp_flag', 'udp'], ['tfo', 'tcp_fast_open_flag', 'tfo'], ['scv', 'skip_cert_verify_flag', 'skip-cert-verify'], ['tls13', 'tls13_flag', 'tls13']] as const) {
      const v = params.get(param) ?? cfg.node_pref[setting]; if (v !== null && v !== undefined && v !== '') n[prop] = bool(v);
    }
  }
  if (bool(params.get('fdn'), bool(cfg.node_pref.filter_deprecated_nodes))) nodes = nodes.filter(n => n.type !== 'ssr' && !(n.type === 'ss' && /^(rc4|bf-|des-|table)/.test(str(n.cipher))));
  if (bool(params.get('sort'), bool(cfg.node_pref.sort_flag))) nodes.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  const used = new Set<string>(); for (const n of nodes) { const original = n.name; let i = 2; while (used.has(n.name)) n.name = `${original} ${i++}`; used.add(n.name); }
  const isValidName = (n: Node) => n.name.length > 0 && n.name.length <= 512 && !/[\r\n\0]/.test(n.name);
  if (!nodes.every(isValidName)) throw new HttpError(400, 'Invalid transformed proxy name');
  const compatibleNodes = nodes.filter(n => compatible(n, target as Target, version));
  if (compatibleNodes.length !== nodes.length) headers.set('X-Subconverter-Skipped-Nodes', String(nodes.length - compatibleNodes.length));
  nodes = compatibleNodes;
  let groupEntries: string[] = [], groups: Dict[] = [], rules: string[] = [], providers: Dict = {};
  if (!simple && !list) {
    groupEntries = params.has('groups') ? lines(b64decode(params.get('groups')!).replace(/@/g, '\n')) : await expandEntries(cfg.proxy_groups.custom_proxy_group, resources.load, 'group');
    groups = makeGroups(preserveSource ? [] : groupEntries, nodes, preserveSource ? sourceData?.groups : []);
    if (preserveSource) rules = sourceData?.rules ?? [];
    if (bool(cfg.rulesets.enabled, true)) {
      const ruleEntries = params.has('ruleset') ? lines(b64decode(params.get('ruleset')!).replace(/@/g, '\n')) : await expandEntries(listValue(cfg.rulesets, 'rulesets', 'ruleset'), resources.load, 'ruleset');
      const built = await buildRules(ruleEntries, resources.load, { target, expand: bool(params.get('expand'), true), classic: bool(params.get('classic')), prefix: str(cfg.managed_config.managed_config_prefix) || new URL(request.url).origin, maxRules: integer(cfg.advanced.max_allowed_rules, 0) });
      rules.push(...built.rules); providers = built.providers;
    }
  }
  let base = '';
  if ((!simple || target === 'sssub') && !list) {
    const baseTarget = target === 'clashr' ? 'clash' : target;
    const path = str(cfg.common[baseTarget + '_rule_base']);
    if (path) base = await renderTemplate(await resources.load(path), templateData(cfg, params, { clash: { new_field_name: String(newFields) } }), resources.load, str(cfg.template.template_path), str(cfg.managed_config.managed_config_prefix) || new URL(request.url).origin);
  }
  const interval = integer(params.get('interval') ?? cfg.managed_config.config_update_interval, 86400), strict = bool(params.get('strict'), bool(cfg.managed_config.config_update_strict));
  const managedLink = profileUrl ?? `${str(cfg.managed_config.managed_config_prefix) || new URL(request.url).origin}/sub?${params.toString()}`;
  const managed = target === 'surge' && bool(cfg.managed_config.write_managed_config, true) ? `#!MANAGED-CONFIG ${managedLink} interval=${interval} strict=${strict}\n` : undefined;
  let script: string | undefined;
  if (bool(params.get('script'))) {
    if (!['clash', 'clashr'].includes(target)) throw new HttpError(422, 'Client script output requires Clash');
    // Client executes this Python-like config, never the Worker.
    const defaultGroup = rules.findLast(r => /^(MATCH|FINAL),/.test(r))?.split(',')[1] ?? 'DIRECT';
    if (rules.some(r => !/^(RULE-SET|MATCH|FINAL),/.test(r))) throw new HttpError(422, 'Client script generation requires remote rule providers (expand=false)');
    script = 'def main(ctx, md):\n' + rules.filter(r => r.startsWith('RULE-SET,')).map(r => { const [, name, group] = r.split(','); return `  if ctx.rule_providers[${JSON.stringify(name)}].match(md):\n    return ${JSON.stringify(group)}\n`; }).join('') + `  return ${JSON.stringify(defaultGroup)}`;
  }
  const body = exportConfig(target as Target, nodes, groups, rules, base, { list, version, newFields, overwrite: bool(cfg.rulesets.overwrite_original_rules), providers, script, managed });
  if (params.get('filename')) headers.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(params.get('filename')!)}`);
  if (!bool(params.get('append_info'), bool(cfg.node_pref.append_sub_userinfo, true))) headers.delete('Subscription-UserInfo');
  headers.set('profile-update-interval', String(Math.max(1, Math.floor(interval / 3600))));
  return { body, headers, target: target as Target };
}
