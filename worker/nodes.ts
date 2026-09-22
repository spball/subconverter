import { parse as yamlParse } from 'yaml';
import { array, b64decode, bool, csv, decode, Dict, HttpError, integer, lines, record, splitOnce, str } from './util';
import { parseIni } from './config';

export const protocols = ['ss', 'ssr', 'vmess', 'vless', 'trojan', 'snell', 'http', 'socks5', 'wireguard', 'hysteria', 'hysteria2', 'tuic', 'anytls', 'mieru'] as const;
export type Protocol = typeof protocols[number];
// Clash-shaped portable fields keep nested transport and protocol options intact.
export interface Node extends Dict { type: Protocol; name: string; server: string; port: number; source: number; group: string; }
export interface Parsed { nodes: Node[]; groups: Dict[]; rules: string[]; }
export function node(data: Dict, source = 0): Node {
  let type = str(data.type).toLowerCase();
  type = ({ shadowsocks: 'ss', shadowsocksr: 'ssr', socks: 'socks5', https: 'http', hy: 'hysteria', hy2: 'hysteria2', mierus: 'mieru' } as Record<string, string>)[type] ?? type;
  if (!protocols.includes(type as Protocol)) throw new HttpError(422, `Unsupported proxy protocol: ${type}`);
  const server = str(data.server).replace(/^\[|\]$/g, '');
  if (!server || /[\s\0\r\n]/.test(server)) throw new HttpError(400, 'Invalid proxy server');
  const port = integer(data.port ?? str(data['port-range']).split('-')[0], 0, 1, 65535), name = str(data.name, `${server}:${port}`);
  if (name.length > 512 || /[\r\n\0]/.test(name)) throw new HttpError(400, 'Invalid proxy name');
  const result: Node = { ...data, name, type: type as Protocol, server, port, source, group: str(data.group, type.toUpperCase()) };
  if (data.type === 'https') result.tls = true;
  if (type === 'ss' && result.plugin === 'obfs') {
    const opts = { ...record(result['plugin-opts']) };
    if (opts.obfs && !opts.mode) { opts.mode = opts.obfs; delete opts.obfs; }
    if (opts['obfs-host'] && !opts.host) { opts.host = opts['obfs-host']; delete opts['obfs-host']; }
    result['plugin-opts'] = opts;
  }
  return result;
}
function uri(raw: string): URL {
  try { return new URL(raw); } catch { throw new HttpError(400, 'Invalid proxy URI'); }
}
export function parseLink(link: string, source = 0): Node {
  if (/^script:/.test(link)) throw new HttpError(422, 'Script subscriptions are not supported');
  if (/^mierus?:\/\//.test(link) && !link.includes('@')) return parseLink('mierus://' + b64decode(link.slice(link.indexOf('://') + 3)), source);
  if (link.startsWith('Netch://')) {
    const d = record(JSON.parse(b64decode(link.slice(8))));
    return node({ ...d, type: str(d.Type).toLowerCase(), name: d.Remark, server: d.Hostname, port: d.Port,
      password: d.Password, cipher: d.EncryptMethod, uuid: d.UserID, alterId: d.AlterID, network: d.TransferProtocol,
      tls: bool(d.TLSSecure), sni: d.ServerName, 'skip-cert-verify': bool(d.AllowInsecure) }, source);
  }
  if (link.startsWith('ssr://')) {
    const raw = b64decode(link.slice(6)); const [main, query] = splitOnce(raw, '/?');
    const m = /^(.*):(\d+):([^:]+):([^:]+):([^:]+):([^:]*)$/.exec(main);
    if (!m) throw new HttpError(400, 'Invalid SSR URI');
    const q = new URLSearchParams(query);
    return node({ type: 'ssr', server: m[1], port: m[2], protocol: m[3], cipher: m[4], obfs: m[5], password: b64decode(m[6]),
      name: q.has('remarks') ? b64decode(q.get('remarks')!) : undefined, group: q.has('group') ? b64decode(q.get('group')!) : undefined,
      'protocol-param': q.has('protoparam') ? b64decode(q.get('protoparam')!) : '', 'obfs-param': q.has('obfsparam') ? b64decode(q.get('obfsparam')!) : '' }, source);
  }
  if (link.startsWith('ss://')) {
    let body = link.slice(5); const [withoutHash, hash] = splitOnce(body, '#'); body = withoutHash;
    const [main, query] = splitOnce(body, '?'); const q = new URLSearchParams(query);
    let authority = main.replace(/\/$/, '');
    if (!authority.includes('@')) authority = b64decode(authority);
    const at = authority.lastIndexOf('@'); if (at < 0) throw new HttpError(400, 'Invalid SS URI');
    let auth = authority.slice(0, at); if (!auth.includes(':')) auth = b64decode(auth); else auth = decode(auth);
    const [cipher, password] = splitOnce(auth, ':'); const u = uri('ss://' + authority.slice(at + 1));
    const [plugin, ...opts] = (q.get('plugin') ?? '').split(';');
    const pluginOpts = Object.fromEntries(opts.filter(Boolean).map(v => v.includes('=') ? splitOnce(v, '=') : [v, true]));
    return node({ type: 'ss', server: u.hostname, port: u.port, cipher, password, name: hash ? decode(hash) : undefined,
      ...(plugin ? { plugin: plugin === 'simple-obfs' || plugin === 'obfs-local' ? 'obfs' : plugin, 'plugin-opts': pluginOpts } : {}) }, source);
  }
  if (link.startsWith('vmess://') && !link.slice(8).includes('@')) {
    const raw = b64decode(link.slice(8));
    if (!raw.trim().startsWith('{')) return parseIniProxy(raw, source);
    const d = record(JSON.parse(raw));
    return node({ type: 'vmess', name: d.ps, server: d.add, port: d.port, uuid: d.id, alterId: integer(d.aid, 0), cipher: str(d.scy, 'auto'),
      network: str(d.net, 'tcp'), tls: d.tls === 'tls', servername: d.sni ?? d.host,
      ...(d.allowInsecure !== undefined ? { 'skip-cert-verify': bool(d.allowInsecure) } : {}),
      ...(d.fp ? { 'client-fingerprint': d.fp } : {}),
      ...transport(str(d.net, 'tcp'), str(d.path), str(d.host), str(d.type)),
      ...(d.alpn ? { alpn: str(d.alpn).split(',') } : {}) }, source);
  }
  if (/^(tg:\/\/|https:\/\/t\.me\/)(socks|http)/.test(link)) {
    const u = uri(link), q = u.searchParams;
    return node({ type: /socks/.test(u.host + u.pathname) ? 'socks5' : 'http', server: q.get('server'), port: q.get('port'),
      username: q.get('user'), password: q.get('pass'), name: q.get('remarks') ?? undefined, group: q.get('group') ?? undefined }, source);
  }
  let u = uri(link.replace(/^trojan-go:/, 'trojan:').replace(/^vless1:/, 'vless:').replace(/^vmess1:/, 'vmess:'));
  // Legacy socks:// base64(user:pass@host:port) links.
  if (/^socks:\/\//.test(link) && !u.port) {
    const [body, hash] = splitOnce(link.slice(8), '#'); u = uri('socks://' + b64decode(body) + (hash ? '#' + hash : ''));
  }
  const q = u.searchParams, type = u.protocol.slice(0, -1), network = q.get('type') ?? q.get('network') ?? 'tcp';
  const d: Dict = { type, server: u.hostname, port: u.port || (/^(https|trojan|hysteria2|hy2|anytls)$/.test(type) ? 443 : 0),
    name: u.hash ? decode(u.hash.slice(1)) : q.get('remarks') ?? undefined,
    group: q.get('group') ?? undefined };
  if (['vless', 'vmess'].includes(type)) Object.assign(d, { uuid: decode(u.username), network,
    tls: ['tls', 'reality'].includes(q.get('security') ?? '') || bool(q.get('tls')),
    cipher: type === 'vmess' ? q.get('encryption') ?? 'auto' : undefined, flow: q.get('flow') ?? undefined,
    ...transport(network, q.get('path') ?? q.get('serviceName') ?? (u.pathname || '/'), q.get('host') ?? q.get('ws.host') ?? q.get('http.host') ?? '', q.get('headerType') ?? '') });
  else if (['http', 'https', 'socks', 'socks5'].includes(type)) Object.assign(d, { username: decode(u.username), password: decode(u.password), tls: type === 'https' });
  else if (type === 'tuic') Object.assign(d, { uuid: decode(u.username), password: decode(u.password), 'congestion-controller': q.get('congestion_control') ?? 'cubic', 'udp-relay-mode': q.get('udp_relay_mode') ?? 'native' });
  else Object.assign(d, { password: decode(u.username + (u.password ? ':' + u.password : '')) || q.get('password') || q.get('auth') || '', tls: true });
  if (type === 'trojan') Object.assign(d, { network, ...transport(network, q.get('path') ?? q.get('wspath') ?? q.get('serviceName') ?? '/', q.get('host') ?? '') });
  if (type === 'mieru' || type === 'mierus') Object.assign(d, { username: decode(u.username), password: decode(u.password), port: u.port || q.get('port')?.split('-')[0], ports: q.get('port') ?? undefined, transport: q.get('protocol') ?? 'TCP', multiplexing: q.get('multiplexing') ?? undefined, tls: undefined });
  if (['hysteria', 'hy'].includes(type)) { d['auth-str'] = q.get('auth') ?? d.password; delete d.password; }
  if (q.get('sni') || q.get('peer') || q.get('tls.servername')) d.sni = q.get('sni') ?? q.get('peer') ?? q.get('tls.servername');
  if (q.has('insecure') || q.has('allowInsecure') || q.has('allowinsecure') || q.has('skip-cert-verify') || q.has('tls.allowinsecure')) d['skip-cert-verify'] = bool(q.get('insecure') ?? q.get('allowInsecure') ?? q.get('allowinsecure') ?? q.get('skip-cert-verify') ?? q.get('tls.allowinsecure'));
  if (q.has('alpn')) d.alpn = q.get('alpn')!.split(',');
  if (q.has('fp') || q.has('fingerprint')) d['client-fingerprint'] = q.get('fp') ?? q.get('fingerprint');
  if (q.has('pbk')) d['reality-opts'] = { 'public-key': q.get('pbk'), 'short-id': q.get('sid') ?? '' };
  for (const [from, to] of Object.entries({ upmbps: 'up', downmbps: 'down', up: 'up', down: 'down', obfs: 'obfs', 'obfs-password': 'obfs-password', mport: 'ports', ports: 'ports', 'auth': 'auth-str' })) if (q.has(from)) d[to] = q.get(from);
  for (const flag of ['udp', 'tfo']) if (q.has(flag)) d[flag] = bool(q.get(flag));
  return node(d, source);
}
function transport(network: string, path: string, host: string, fake = ''): Dict {
  if (network === 'ws') return { 'ws-opts': { path: path || '/', headers: host ? { Host: host } : {} } };
  if (network === 'grpc') return { 'grpc-opts': { 'grpc-service-name': path } };
  if (network === 'http' || network === 'h2' || fake === 'http') return { 'http-opts': { path: [path || '/'], headers: host ? { Host: host.split(',') } : {} } };
  return {};
}
export function fromSingbox(d: Dict, source: number): Node {
  const tls = record(d.tls), transportData = record(d.transport), utls = record(tls.utls), reality = record(tls.reality);
  const type = str(d.type), t = str(transportData.type);
  const out: Dict = { ...d, type, name: d.tag, server: d.server, port: d.server_port,
    tls: bool(tls.enabled), sni: tls.server_name, 'skip-cert-verify': tls.insecure, alpn: tls.alpn,
    network: t || 'tcp', cipher: d.method ?? d.security, alterId: d.alter_id, 'client-fingerprint': utls.fingerprint, tfo: d.tcp_fast_open,
    'dialer-proxy': d.detour, 'congestion-controller': d.congestion_control, 'udp-relay-mode': d.udp_relay_mode,
    'reduce-rtt': d.zero_rtt_handshake, up: d.up_mbps, down: d.down_mbps,
    ...transport(t, str(transportData.path ?? transportData.service_name), str(record(transportData.headers).Host)) };
  if (reality.enabled) out['reality-opts'] = { 'public-key': reality.public_key, 'short-id': reality.short_id };
  if (d.plugin) { out.plugin = d.plugin; out['plugin-opts'] = Object.fromEntries(str(d.plugin_opts).split(';').filter(Boolean).map(v => splitOnce(v, '='))); }
  if (type === 'hysteria') { out['auth-str'] = d.auth_str ?? d.auth; out.obfs = d.obfs; }
  if (type === 'hysteria2') { out.obfs = record(d.obfs).type; out['obfs-password'] = record(d.obfs).password; }
  if (type === 'wireguard') Object.assign(out, { 'private-key': d.private_key, 'public-key': d.peer_public_key, 'pre-shared-key': d.pre_shared_key,
    ip: array(d.local_address).find(v => !str(v).includes(':')), ipv6: array(d.local_address).find(v => str(v).includes(':')), mtu: d.mtu, reserved: d.reserved });
  for (const k of ['tag', 'server_port', 'transport', 'method', 'tcp_fast_open', 'detour']) delete out[k];
  return node(out, source);
}
export function parseIniProxy(line: string, source = 0): Node {
  const [left, right] = splitOnce(line, '='); if (!right) throw new HttpError(400, 'Invalid proxy configuration');
  const parts = csv(right); const isQx = ['shadowsocks', 'vmess', 'vless', 'trojan', 'http', 'socks5', 'hysteria2'].includes(left.trim().toLowerCase()) && /^\[?.+\]?:\d+$/.test(parts[0]);
  let type = isQx ? left.trim().toLowerCase() : parts.shift()!.toLowerCase();
  const data: Dict = { type, name: isQx ? undefined : left.trim() };
  const options: Dict = {};
  if (isQx) { const m = /^(.*):(\d+)$/.exec(parts.shift()!)!; data.server = m[1]; data.port = m[2]; }
  else { data.server = parts.shift(); data.port = parts.shift(); }
  const positional: string[] = [];
  for (const p of parts) { if (p.includes('=')) { const [k, v] = splitOnce(p, '='); options[k.trim()] = v.trim(); } else positional.push(p); }
  if (isQx) { data.name = options.tag; if (options['ssr-protocol']) type = 'ssr'; }
  if (type === 'shadowsocks' || type === 'custom') type = 'ss';
  if (type === 'shadowsocksr') type = 'ssr';
  data.type = type;
  data.password = options.password ?? positional[1]; data.username = options.username;
  data.cipher = options['encrypt-method'] ?? options.method ?? positional[0];
  if (['vmess', 'vless'].includes(type)) { data.uuid = options.username ?? options.password ?? (type === 'vmess' && positional.length > 1 ? positional[1] : positional[0]); data.cipher = options.method ?? (type === 'vmess' && positional.length > 1 ? positional[0] : 'auto'); data.alterId = integer(options['alter-id'], 0); delete data.password; }
  if (['trojan', 'snell', 'hysteria2', 'anytls'].includes(type)) data.password = options.password ?? options.psk ?? positional[0];
  if (type === 'snell') data.version = integer(options.version, 3);
  if (['socks5', 'http', 'https'].includes(type) && positional.length) { data.username = positional[0]; data.password = positional[1]; }
  data.tls = type === 'https' || ['trojan', 'hysteria2', 'anytls'].includes(type) || bool(options.tls ?? options['over-tls']) || ['wss', 'over-tls'].includes(str(options.obfs));
  data.sni = options.sni ?? options['tls-host'] ?? options['tls-name'] ?? (data.tls ? options['obfs-host'] : undefined);
  if (options['skip-cert-verify'] !== undefined) data['skip-cert-verify'] = bool(options['skip-cert-verify']);
  if (options['tls-verification'] !== undefined) data['skip-cert-verify'] = !bool(options['tls-verification'], true);
  if (options.certificate !== undefined) data['skip-cert-verify'] = options.certificate === '0';
  if (options.group) data.group = options.group;
  if (options['udp-relay'] !== undefined) data.udp = bool(options['udp-relay']);
  if (options['udp'] !== undefined) data.udp = bool(options.udp);
  if (options['tfo'] !== undefined || options['fast-open'] !== undefined) data.tfo = bool(options.tfo ?? options['fast-open']);
  if (type === 'ssr') Object.assign(data, { protocol: options.protocol ?? options['ssr-protocol'] ?? positional[2], obfs: options.obfs ?? positional[4] ?? 'plain',
    'protocol-param': options['protocol-param'] ?? options.protocol_param ?? options['ssr-protocol-param'] ?? positional[3], 'obfs-param': options['obfs-param'] ?? options.obfs_param ?? options['obfs-host'] ?? positional[5] });
  else if (type === 'ss' && (options.obfs || positional[2])) {
    const obfs = options.obfs ?? positional[2];
    if (['http', 'tls'].includes(str(obfs))) Object.assign(data, { plugin: 'obfs', 'plugin-opts': { mode: obfs, host: options['obfs-host'] ?? positional[3] } });
    else if (['ws', 'wss'].includes(str(obfs))) Object.assign(data, { plugin: 'v2ray-plugin', 'plugin-opts': { mode: 'websocket', tls: obfs === 'wss', host: options['obfs-host'], path: options['obfs-uri'] ?? '/' } });
  }
  const net = options.transport ?? (bool(options.ws) || ['ws', 'wss'].includes(str(options.obfs)) ? 'ws' : 'tcp');
  if (net !== 'tcp') Object.assign(data, { network: net, ...transport(str(net), str(options['ws-path'] ?? options['obfs-uri'] ?? options['obfs-path'] ?? options.path, '/'), str(options['obfs-host'] ?? options.host)) });
  if (options['obfs-header']) data['ws-opts'] = { ...record(data['ws-opts']), headers: Object.fromEntries(str(options['obfs-header']).split('[Rr][Nn]').map(v => { const [k, val] = splitOnce(v, ':'); return [k.trim(), val.trim()]; })) };
  if (options['ws-headers']) data['ws-opts'] = { ...record(data['ws-opts']), headers: Object.fromEntries(str(options['ws-headers']).split('|').map(v => splitOnce(v, ':'))) };
  if (options['public-key'] || options['reality-base64-pubkey']) data['reality-opts'] = { 'public-key': options['public-key'] ?? options['reality-base64-pubkey'], 'short-id': options['short-id'] ?? options['reality-hex-shortid'] ?? '' };
  if (options.flow || options['vless-flow']) data.flow = options.flow ?? options['vless-flow'];
  if (options['vmess-aead'] !== undefined) data.alterId = bool(options['vmess-aead']) ? 0 : 64;
  if (options['download-bandwidth']) data.down = options['download-bandwidth'];
  if (options['port-hopping']) data.ports = options['port-hopping'];
  return node(data, source);
}
export function parseSubscription(text: string, source = 0, depth = 0): Parsed {
  try { return parseSubscriptionInner(text, source, depth); }
  catch (e) { if (e instanceof HttpError) throw e; throw new HttpError(400, 'Invalid subscription data'); }
}
function parseSubscriptionInner(text: string, source = 0, depth = 0): Parsed {
  if (depth > 2) throw new HttpError(400, 'Invalid nested subscription');
  text = text.trim().replace(/^\uFEFF/, ''); if (!text) throw new HttpError(400, 'Empty subscription');
  const result: Parsed = { nodes: [], groups: [], rules: [] };
  if (text.startsWith('ssd://')) {
    const d = record(JSON.parse(b64decode(text.slice(6))));
    result.nodes = array(d.servers).map(item => { const s = record(item); return node({ type: 'ss', server: s.server, port: s.port ?? d.port,
      password: s.password ?? d.password, cipher: s.encryption ?? d.encryption, name: s.remarks, group: d.airport,
      ...(s.plugin ? { plugin: s.plugin, 'plugin-opts': s.plugin_options } : {}) }, source); });
  } else if (/^(?:\{|\[\s*\{)/.test(text)) {
    let parsed: unknown; try { parsed = JSON.parse(text); } catch { throw new HttpError(400, 'Invalid subscription JSON'); }
    const d = record(parsed);
    if (Array.isArray(d.proxies) || Array.isArray(d.Proxy)) {
      result.nodes = array(d.proxies ?? d.Proxy).map(v => node(record(v), source)); result.groups = array(d['proxy-groups'] ?? d['Proxy Group']).map(record); result.rules = array(d.rules ?? d.Rule).map(v => str(v));
    } else if (Array.isArray(d.outbounds)) result.nodes = d.outbounds.map(record).filter(v => v.server).map(v => fromSingbox(v, source));
    else if (Array.isArray(d.servers) || Array.isArray(parsed)) result.nodes = array(d.servers ?? parsed).map(v => { const p = record(v); return node({ ...p, type: 'ss', name: p.remarks, port: p.server_port, cipher: p.method }, source); });
    else if (d.server && d.server_port) result.nodes = [node({ ...d, type: 'ss', port: d.server_port, cipher: d.method, name: d.remarks }, source)];
    else throw new HttpError(422, 'Unsupported JSON subscription structure');
  } else if (/^(?:["']?(?:proxies|Proxy)["']?\s*:)/m.test(text)) {
    const d = record(yamlParse(text, { maxAliasCount: 50 }));
    result.nodes = array(d.proxies ?? d.Proxy).map(v => node(record(v), source));
    result.groups = array(d['proxy-groups'] ?? d['Proxy Group']).map(record); result.rules = array(d.rules ?? d.Rule).map(v => str(v));
  } else if (/^\[(?:Proxy|server_local|Endpoint|SERVER)\]/im.test(text)) {
    const ini = parseIni(text, true);
    const section = ini.Proxy ?? ini.proxy ?? ini.server_local ?? ini.SERVER ?? ini.Endpoint ?? {};
    for (const [k, values] of Object.entries(section)) for (const v of values) {
      const line = k === '__lines' ? v : k + '=' + v;
      if (/=\s*(direct|reject|reject-tinygif)\s*$/i.test(line)) continue;
      if (/=\s*wireguard,/i.test(line)) {
        const [name, data] = splitOnce(line, '=');
        const sectionName = /section-name\s*=\s*([^,]+)/.exec(data)?.[1];
        const section = sectionName ? ini['WireGuard ' + sectionName.trim()] ?? {} : {};
        const value = (key: string) => section[key]?.[0] ?? new RegExp('(?:^|[,({])\\s*' + key + '\\s*=\\s*([^,)}]+)').exec(data)?.[1]?.trim();
        const peer = section.peer?.[0] ?? data;
        const endpoint = /endpoint\s*=\s*(\[[^\]]+\]|[^:, )}]+):(\d+)/.exec(peer);
        if (!endpoint) throw new HttpError(400, 'Missing WireGuard endpoint');
        result.nodes.push(node({ name: name.trim(), type: 'wireguard', server: endpoint[1], port: endpoint[2],
          ip: value('self-ip') ?? value('interface-ip'), ipv6: value('self-ip-v6') ?? value('interface-ipv6'),
          'private-key': value('private-key'), 'public-key': /public-key\s*=\s*([^,)}]+)/.exec(peer)?.[1]?.trim(),
          'pre-shared-key': value('preshared-key'), mtu: value('mtu'), 'keepalive': value('keepalive') }, source));
      } else if (ini.Endpoint) {
        const p = csv(line);
        if (p[1] === 'ss' || p[1] === 'vmess1') { const n = parseLink(p[2], source); n.name = p[0]; result.nodes.push(n); }
        else if (p[1] === 'builtin' && ['socks', 'http'].includes(p[2])) {
          const fields = Object.fromEntries(p.slice(3).map(v => splitOnce(v, '=')));
          result.nodes.push(node({ name: p[0], type: p[2], server: fields.address, port: fields.port, username: fields.user, password: fields.pass }, source));
        }
      } else result.nodes.push(parseIniProxy(line, source));
    }
    for (const [name, values] of Object.entries(ini['Proxy Group'] ?? ini['policy'] ?? {})) for (const value of values) {
      const [type, ...members] = csv(value); const params = Object.fromEntries(members.filter(v => v.includes('=')).map(v => splitOnce(v, '=')));
      result.groups.push({ name, type, proxies: members.filter(v => !v.includes('=')), ...params });
    }
    for (const sectionName of ['Rule', 'rule', 'filter_local', 'RoutingRule']) {
      for (const [k, values] of Object.entries(ini[sectionName] ?? {})) result.rules.push(...(k === '__lines' ? values : values.map(v => k + '=' + v)));
    }
  } else if (/^(?:shadowsocks|vmess|trojan|vless|http|socks5)\s*=/m.test(text)) result.nodes = lines(text).map(v => parseIniProxy(v, source));
  else if (/^[A-Za-z0-9+/=_\s-]+$/.test(text)) return parseSubscription(b64decode(text), source, depth + 1);
  else result.nodes = lines(text).flatMap(v => v.split(/\s+(?=[a-z0-9-]+:\/\/)/i)).map(v => parseLink(v, source));
  if (!result.nodes.length) throw new HttpError(400, 'No valid nodes found');
  if (result.nodes.length > 2000) throw new HttpError(413, 'Node limit exceeded (2000)');
  return result;
}
