import { stringify as yamlStringify, parse as yamlParse } from 'yaml';
import { Node } from './nodes';
import { array, b64encode, bool, Dict, HttpError, record, str } from './util';

export const targets = ['clash', 'clashr', 'surge', 'surfboard', 'quan', 'quanx', 'loon', 'mellow', 'singbox', 'ss', 'ssr', 'sssub', 'ssd', 'v2ray', 'trojan', 'vless', 'hysteria2', 'mixed'] as const;
export type Target = typeof targets[number];
export const simpleTargets = new Set<string>(['ss', 'ssr', 'sssub', 'ssd', 'v2ray', 'trojan', 'vless', 'hysteria2', 'mixed']);
export function host(n: Node): string { return n.server.includes(':') ? `[${n.server}]` : n.server; }
function clean(d: Dict): Dict { return Object.fromEntries(Object.entries(d).filter(([, v]) => v !== undefined)); }
const enc = (v: unknown) => encodeURIComponent(str(v));
export function toClash(n: Node): Dict {
  const { source: _source, group: _group, ...portable } = n;
  const d: Dict = portable;
  // Only pass through Clash input extensions, not sing-box transport fields.
  for (const k of ['server_port', 'up_mbps', 'down_mbps', 'congestion_control', 'udp_relay_mode', 'zero_rtt_handshake', 'auth_str', 'local_address', 'peer_public_key', 'private_key', 'pre_shared_key', 'plugin_opts']) delete d[k];
  if (d.type === 'vmess' || d.type === 'vless') { d.servername ??= d.sni; delete d.sni; }
  if (d.type !== 'vmess') delete d.alterId;
  if (!['vmess', 'ss', 'ssr'].includes(str(d.type))) delete d.cipher;
  if (n.type === 'mieru' && (n.ports || n['port-range'])) { d['port-range'] = n.ports ?? n['port-range']; delete d.ports; delete d.port; }
  return clean(d);
}
export function toSingbox(n: Node): Dict {
  const tls: Dict = { enabled: bool(n.tls, ['trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls'].includes(n.type)), server_name: n.sni ?? n.servername,
    insecure: n['skip-cert-verify'], alpn: n.alpn };
  if (n['client-fingerprint']) tls.utls = { enabled: true, fingerprint: n['client-fingerprint'] };
  if (n['reality-opts']) tls.reality = { enabled: true, public_key: record(n['reality-opts'])['public-key'], short_id: record(n['reality-opts'])['short-id'] };
  const d: Dict = { type: n.type === 'ss' ? 'shadowsocks' : n.type === 'socks5' ? 'socks' : n.type, tag: n.name,
    server: n.server, server_port: n.port, tcp_fast_open: n.tfo, detour: n['dialer-proxy'] };
  if (['ss', 'ssr', 'trojan', 'hysteria2', 'tuic', 'anytls', 'http', 'socks5', 'mieru'].includes(n.type)) d.password = n.password;
  if (['vmess', 'vless', 'tuic'].includes(n.type)) d.uuid = n.uuid;
  if (['http', 'socks5', 'mieru'].includes(n.type)) d.username = n.username;
  if (n.type === 'ss') { d.method = n.cipher; d.plugin = n.plugin; if (n['plugin-opts']) d.plugin_opts = Object.entries(record(n['plugin-opts'])).map(([k, v]) => v === true ? k : `${k}=${str(v)}`).join(';'); }
  if (n.type === 'ssr') Object.assign(d, { method: n.cipher, protocol: n.protocol, protocol_param: n['protocol-param'], obfs: n.obfs, obfs_param: n['obfs-param'] });
  if (n.type === 'vmess') Object.assign(d, { security: n.cipher ?? 'auto', alter_id: n.alterId ?? 0 });
  if (n.type === 'vless') d.flow = n.flow;
  if (n.type === 'hysteria') Object.assign(d, { auth_str: n['auth-str'], obfs: n.obfs, up_mbps: n.up, down_mbps: n.down });
  if (n.type === 'hysteria2') Object.assign(d, { up_mbps: n.up, down_mbps: n.down, ...(n.obfs ? { obfs: { type: n.obfs, password: n['obfs-password'] } } : {}) });
  if (n.type === 'tuic') Object.assign(d, { congestion_control: n['congestion-controller'], udp_relay_mode: n['udp-relay-mode'], zero_rtt_handshake: n['reduce-rtt'] });
  if (n.type === 'wireguard') Object.assign(d, { local_address: [n.ip, n.ipv6].filter(Boolean), private_key: n['private-key'], peer_public_key: n['public-key'], pre_shared_key: n['pre-shared-key'], mtu: n.mtu, reserved: n.reserved });
  if (n.type === 'snell' || n.type === 'mieru') throw new HttpError(422, `sing-box cannot represent ${n.type}`);
  if (tls.enabled || n['reality-opts']) d.tls = clean(tls);
  const network = str(n.network, 'tcp');
  if (network === 'ws') { const ws = record(n['ws-opts']); d.transport = clean({ type: 'ws', path: ws.path ?? '/', headers: ws.headers, max_early_data: ws['max-early-data'], early_data_header_name: ws['early-data-header-name'] }); }
  else if (network === 'grpc') d.transport = { type: 'grpc', service_name: record(n['grpc-opts'])['grpc-service-name'] ?? '' };
  else if (network === 'http' || network === 'h2') { const h = record(n['http-opts'] ?? n['h2-opts']); d.transport = { type: 'http', path: array(h.path)[0] ?? '/', host: record(h.headers).Host ?? h.host }; }
  else if (network !== 'tcp') throw new HttpError(422, `Unsupported sing-box transport: ${network}`);
  return clean(d);
}
export function toLink(n: Node): string | undefined {
  const address = host(n) + ':' + n.port, hash = '#' + enc(n.name);
  if (n.type === 'ss') {
    let query = '';
    if (n.plugin) {
      const opts = Object.entries(record(n['plugin-opts'])).map(([k, v]) => `${n.plugin === 'obfs' ? k === 'mode' ? 'obfs' : k === 'host' ? 'obfs-host' : k : k}=${str(v)}`).join(';');
      query = '/?plugin=' + enc((n.plugin === 'obfs' ? 'obfs-local' : str(n.plugin)) + (opts ? ';' + opts : ''));
    }
    return `ss://${b64encode(str(n.cipher) + ':' + str(n.password), true)}@${address}${query}${hash}`;
  }
  if (n.type === 'ssr') {
    const query = `obfsparam=${b64encode(str(n['obfs-param']), true)}&protoparam=${b64encode(str(n['protocol-param']), true)}&remarks=${b64encode(n.name, true)}&group=${b64encode(n.group, true)}`;
    return 'ssr://' + b64encode(`${address}:${str(n.protocol, 'origin')}:${str(n.cipher)}:${str(n.obfs, 'plain')}:${b64encode(str(n.password), true)}/?${query}`, true);
  }
  if (n.type === 'vmess') {
    const net = str(n.network, 'tcp'), ws = record(n['ws-opts']), h = record(n['http-opts']);
    return 'vmess://' + b64encode(JSON.stringify({ v: '2', ps: n.name, add: n.server, port: String(n.port), id: n.uuid, aid: String(n.alterId ?? 0), scy: n.cipher ?? 'auto', net,
      type: 'none', host: record(ws.headers).Host ?? array(record(h.headers).Host)[0] ?? '', path: ws.path ?? record(n['grpc-opts'])['grpc-service-name'] ?? array(h.path)[0] ?? '',
      tls: bool(n.tls) ? 'tls' : '', sni: n.servername ?? n.sni ?? '', alpn: array(n.alpn).join(','), allowInsecure: n['skip-cert-verify'], fp: n['client-fingerprint'] }));
  }
  if (!['vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls', 'http', 'socks5'].includes(n.type)) return undefined;
  const q = new URLSearchParams();
  if (n.sni ?? n.servername) q.set('sni', str(n.sni ?? n.servername));
  if (n['skip-cert-verify'] !== undefined) q.set('insecure', bool(n['skip-cert-verify']) ? '1' : '0');
  if (n.alpn) q.set('alpn', array(n.alpn).join(','));
  if (n['client-fingerprint']) q.set('fp', str(n['client-fingerprint']));
  if (n.type === 'vless') {
    q.set('encryption', 'none'); q.set('security', n['reality-opts'] ? 'reality' : bool(n.tls) ? 'tls' : 'none');
    q.set('type', str(n.network, 'tcp')); if (n.flow) q.set('flow', str(n.flow));
    if (n['reality-opts']) { q.set('pbk', str(record(n['reality-opts'])['public-key'])); q.set('sid', str(record(n['reality-opts'])['short-id'])); }
  }
  if (n.network === 'ws') { q.set('type', 'ws'); q.set('path', str(record(n['ws-opts']).path, '/')); const h = record(record(n['ws-opts']).headers).Host; if (h) q.set('host', str(h)); }
  if (n.network === 'grpc') { q.set('type', 'grpc'); q.set('serviceName', str(record(n['grpc-opts'])['grpc-service-name'])); }
  for (const [key, value] of Object.entries({ upmbps: n.up, downmbps: n.down, obfs: n.obfs, 'obfs-password': n['obfs-password'], mport: n.ports, auth: n['auth-str'], congestion_control: n['congestion-controller'], udp_relay_mode: n['udp-relay-mode'] })) if (value !== undefined && value !== '') q.set(key, str(value));
  const auth = n.type === 'vless' ? enc(n.uuid) : n.type === 'tuic' ? `${enc(n.uuid)}:${enc(n.password)}` : ['http', 'socks5'].includes(n.type) ? `${enc(n.username)}:${enc(n.password)}` : enc(n.password ?? n['auth-str']);
  const scheme = n.type === 'http' && n.tls ? 'https' : n.type === 'socks5' ? 'socks' : n.type;
  return `${scheme}://${auth}@${address}${q.size ? '?' + q.toString() : ''}${hash}`;
}
export function compatible(n: Node, target: Target, version = 4): boolean {
  if (target === 'surge' && version < 4 && ['vmess', 'hysteria2', 'anytls', 'wireguard'].includes(n.type)) return false;
  const types: Partial<Record<Target, string[]>> = {
    ss: ['ss'], ssr: ['ssr'], sssub: ['ss'], ssd: ['ss'], v2ray: ['vmess'], trojan: ['trojan'], vless: ['vless'], hysteria2: ['hysteria2'],
    surge: version === 2 ? ['ss', 'http', 'socks5'] : ['ss', 'vmess', 'trojan', 'snell', 'http', 'socks5', 'hysteria2', 'anytls', 'wireguard'],
    surfboard: ['ss', 'vmess', 'trojan', 'http', 'socks5'],
    quan: ['ss', 'ssr', 'vmess', 'http', 'socks5'], quanx: ['ss', 'ssr', 'vmess', 'vless', 'trojan', 'http', 'socks5'],
    loon: ['ss', 'ssr', 'vmess', 'vless', 'trojan', 'http', 'socks5', 'hysteria2', 'wireguard'],
    mellow: ['ss', 'vmess', 'http', 'socks5'], singbox: ['ss', 'ssr', 'vmess', 'vless', 'trojan', 'http', 'socks5', 'wireguard', 'hysteria', 'hysteria2', 'tuic', 'anytls'],
    mixed: ['ss', 'ssr', 'vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls', 'http', 'socks5']
  };
  return !types[target] || types[target]!.includes(n.type);
}
const quote = (v: unknown): string => /[,\r\n"=]/.test(str(v)) ? JSON.stringify(str(v)) : str(v);
export function toIni(n: Node, target: Target, version = 4): string {
  const qx = target === 'quanx', loon = target === 'loon', quan = target === 'quan';
  if (target === 'mellow') {
    if (n.type === 'ss') return `${quote(n.name)}, ss, ${toLink(n)!.split('#')[0]}`;
    if (n.type === 'vmess') {
      const ws = record(n['ws-opts']); const q = new URLSearchParams({ network: str(n.network, 'tcp'), tls: String(bool(n.tls)) });
      if (record(ws.headers).Host) q.set('ws.host', str(record(ws.headers).Host));
      if (n.sni ?? n.servername) q.set('tls.servername', str(n.sni ?? n.servername));
      if (n['skip-cert-verify'] !== undefined) q.set('tls.allowinsecure', String(bool(n['skip-cert-verify'])));
      return `${quote(n.name)}, vmess1, vmess1://${enc(n.uuid)}@${host(n)}:${n.port}${str(ws.path, '/')}?${q.toString()}`;
    }
    return `${quote(n.name)}, builtin, ${n.type === 'socks5' ? 'socks' : 'http'}, address=${host(n)}, port=${n.port}, user=${quote(n.username)}, pass=${quote(n.password)}`;
  }
  if (n.type === 'wireguard') {
    if (target === 'surge') return `${quote(n.name)}=wireguard, section-name=wg_${n.source}_${n.port}_${encodeURIComponent(n.name)}`;
    const peer = `public-key=${quote(n['public-key'])}, endpoint=${host(n)}:${n.port}, allowed-ips="${array(n['allowed-ips'] ?? ['0.0.0.0/0', '::/0']).join(',')}"${n.reserved ? ', reserved=[' + array(n.reserved).join(',') + ']' : ''}`;
    return `${quote(n.name)}=wireguard, interface-ip=${str(n.ip)}, private-key=${str(n['private-key'])}${n.ipv6 ? ', interface-ipv6=' + str(n.ipv6) : ''}, peers=[{${peer}}]`;
  }
  if (target === 'surge' && version === 2 && n.type === 'ss') return `${quote(n.name)}=custom, ${host(n)}, ${n.port}, ${quote(n.cipher)}, ${quote(n.password)}, https://github.com/pobizhe/SSEncrypt/raw/master/SSEncrypt.module`;
  const type = n.type === 'ss' && (qx || loon || quan) ? 'shadowsocks' : n.type === 'ssr' && (loon || quan) ? 'shadowsocksr' : n.type === 'http' && n.tls ? 'https' : n.type;
  const values = qx ? [`${n.type === 'ssr' ? 'shadowsocks' : type}=${host(n)}:${n.port}`] : [`${quote(n.name)}=${type}`, host(n), String(n.port)];
  const add = (k: string, v: unknown) => { if (v !== undefined && v !== '') values.push(`${k}=${quote(v)}`); };
  if (['ss', 'ssr'].includes(n.type)) {
    if (loon || quan) values.push(quote(n.cipher), quote(n.password));
    else { add(qx ? 'method' : 'encrypt-method', n.cipher); add('password', n.password); }
    if (n.type === 'ssr') { add(qx ? 'ssr-protocol' : 'protocol', n.protocol); add(qx ? 'ssr-protocol-param' : 'protocol-param', n['protocol-param']); add('obfs', n.obfs); add(qx ? 'obfs-host' : 'obfs-param', n['obfs-param']); }
    if (n.plugin === 'obfs') { add('obfs', record(n['plugin-opts']).mode); add('obfs-host', record(n['plugin-opts']).host); }
    else if (n.plugin) throw new HttpError(422, `${target} cannot represent this SS plugin`);
  } else if (['vmess', 'vless'].includes(n.type)) {
    if ((loon || quan) && n.type === 'vmess') values.push(quote(n.cipher === 'auto' || !n.cipher ? 'chacha20-ietf-poly1305' : n.cipher), quote(n.uuid));
    else if (loon) values.push(quote(n.uuid)); else add(qx ? 'password' : 'username', n.uuid);
    if (qx) add('method', n.cipher ?? 'aes-128-gcm');
    if (n.type === 'vmess' && !qx && !loon && !quan) add('vmess-aead', Number(n.alterId ?? 0) === 0);
  } else if (n.type === 'snell') { add('psk', n.password); add('version', n.version ?? 3); }
  else { add('username', n.username); if (loon && n.type === 'trojan') values.push(quote(n.password)); else add('password', n.password); }
  if (quan) add('group', n.group);
  if (n.tls !== undefined) add(qx || loon || quan ? 'over-tls' : 'tls', bool(n.tls));
  add(qx || quan ? 'tls-host' : loon ? 'tls-name' : 'sni', n.sni ?? n.servername);
  if (n['skip-cert-verify'] !== undefined) add(qx ? 'tls-verification' : 'skip-cert-verify', qx ? !bool(n['skip-cert-verify']) : bool(n['skip-cert-verify']));
  if (n.udp !== undefined) add('udp-relay', n.udp);
  if (n.tfo !== undefined) add(qx ? 'fast-open' : 'tfo', n.tfo);
  if (n.network === 'ws') {
    const ws = record(n['ws-opts']), headers = record(ws.headers);
    if (qx) { add('obfs', n.tls ? 'wss' : 'ws'); add('obfs-uri', ws.path ?? '/'); add('obfs-host', headers.Host); }
    else if (loon) { add('transport', 'ws'); add('path', ws.path ?? '/'); add('host', headers.Host); }
    else if (quan) { add('obfs', 'ws'); add('obfs-path', ws.path ?? '/'); add('obfs-header', Object.entries(headers).map(([k, v]) => k + ': ' + str(v)).join('[Rr][Nn]')); }
    else { add('ws', true); add('ws-path', ws.path ?? '/'); add('ws-headers', Object.entries(headers).map(([k, v]) => k + ':' + str(v)).join('|')); }
  } else if (n.network && n.network !== 'tcp') throw new HttpError(422, `${target} cannot represent transport ${str(n.network)}`);
  if (n['reality-opts']) {
    if (loon) { add('flow', n.flow); add('public-key', record(n['reality-opts'])['public-key']); add('short-id', record(n['reality-opts'])['short-id']); }
    else if (qx) { add('obfs', 'over-tls'); add('obfs-host', n.sni ?? n.servername); add('reality-base64-pubkey', record(n['reality-opts'])['public-key']); add('reality-hex-shortid', record(n['reality-opts'])['short-id']); add('vless-flow', n.flow); }
    else throw new HttpError(422, `${target} Reality output is not supported`);
  }
  if (n.type === 'hysteria2') { add('download-bandwidth', n.down); add('port-hopping', n.ports); }
  if (n.tls13 !== undefined) add('tls13', n.tls13);
  if (qx) add('tag', n.name);
  return values.join(', ');
}
export interface ExportOptions { list: boolean; version: number; newFields: boolean; overwrite: boolean; providers?: Dict; script?: string; managed?: string; }
export function exportConfig(target: Target, nodes: Node[], groups: Dict[], rules: string[], base: string, opts: ExportOptions): string {
  if (!nodes.length) throw new HttpError(400, 'No nodes are compatible with target');
  if (!['clash', 'clashr'].includes(target) && groups.some(g => array(g.use).length || ['relay', 'smart'].includes(str(g.type)))) throw new HttpError(422, 'Provider, relay and smart groups require Clash output');
  if (target === 'sssub') {
    const root = base.trim() ? record(JSON.parse(base)) : {};
    const servers = nodes.map(n => clean({ ...root, remarks: n.name, server: n.server, server_port: n.port, password: n.password, method: n.cipher,
      plugin: n.plugin, plugin_opts: n['plugin-opts'] ? Object.entries(record(n['plugin-opts'])).map(([k, v]) => k + '=' + str(v)).join(';') : undefined }));
    return JSON.stringify(servers, null, 2);
  }
  if (target === 'ssd') return 'ssd://' + b64encode(JSON.stringify({ airport: nodes[0].group, port: nodes[0].port, encryption: nodes[0].cipher, password: nodes[0].password,
    servers: nodes.map((n, i) => ({ id: i, server: n.server, port: n.port, encryption: n.cipher, password: n.password, remarks: n.name })) }));
  if (simpleTargets.has(target)) { const links = nodes.map(toLink).filter(Boolean).join('\n') + '\n'; return opts.list ? links : b64encode(links); }
  if (target === 'clash' || target === 'clashr') {
    const root = opts.list ? {} : base.trim() ? record(yamlParse(base, { maxAliasCount: 50 })) : { 'mixed-port': 7890, mode: 'rule' };
    const pk = opts.newFields ? 'proxies' : 'Proxy', gk = opts.newFields ? 'proxy-groups' : 'Proxy Group', rk = opts.newFields ? 'rules' : 'Rule';
    const oldRules = array(root.rules ?? root.Rule).map(v => str(v));
    const originalGroups = array(root['proxy-groups'] ?? root['Proxy Group']).map(record);
    const mergedGroups = originalGroups.map(g => groups.find(next => next.name === g.name) ?? g);
    mergedGroups.push(...groups.filter(g => !originalGroups.some(old => old.name === g.name)));
    for (const k of ['Proxy', 'Proxy Group', 'Rule', 'proxies', 'proxy-groups', 'rules']) delete root[k];
    root[pk] = nodes.map(toClash);
    if (!opts.list) { root[gk] = mergedGroups; root[rk] = [...(opts.overwrite ? [] : oldRules), ...rules]; }
    if (opts.providers && Object.keys(opts.providers).length) root['rule-providers'] = { ...record(root['rule-providers']), ...opts.providers };
    if (opts.script) root.script = { code: opts.script };
    return yamlStringify(root, { lineWidth: 0 });
  }
  if (target === 'singbox') {
    const root = opts.list ? {} : base.trim() ? record(JSON.parse(base)) : {};
    root.outbounds = [...nodes.map(toSingbox), ...(!opts.list ? groups.map(g => ({ type: g.type === 'select' ? 'selector' : 'urltest', tag: g.name, outbounds: g.proxies,
      ...(g.type !== 'select' ? { url: g.url, interval: `${str(g.interval, '300')}s`, tolerance: g.tolerance } : {}) })) : []), ...(!opts.list ? [{ type: 'direct', tag: 'DIRECT' }, { type: 'block', tag: 'REJECT' }] : [])];
    if (!opts.list) {
      const route = record(root.route), converted = rules.map(singboxRule);
      const final = rules.findLast(r => /^(MATCH|FINAL),/.test(r));
      root.route = { ...route, rules: [...(opts.overwrite ? [] : array(route.rules)), ...converted.filter(Boolean)], ...(final ? { final: final.split(',')[1] } : {}) };
    }
    return JSON.stringify(root, null, 2);
  }
  let body = nodes.map(n => toIni(n, target, opts.version)).join('\n') + '\n';
  if (opts.list) return target === 'quan' ? b64encode(nodes.map(n => n.type === 'vmess' ? 'vmess://' + b64encode(toIni(n, target), true) : toLink(n)).filter(Boolean).join('\n')) : body;
  const groupLines = groups.map(g => {
    if (target === 'mellow') return `${quote(g.name)}, ${array(g.proxies).map(quote).join(':')}, latency, interval=300, timeout=6`;
    if (target === 'quan') { const type = array(g.proxies).length < 2 || g.type === 'select' || g.type === 'fallback' ? 'static' : g.type === 'url-test' ? 'auto' : 'balance, round-robin'; return b64encode(`${str(g.name)} : ${type}${type === 'static' ? ', ' + str(array(g.proxies)[0]) : ''}\n${array(g.proxies).join('\n')}\n`); }
    if (target === 'quanx') return `${array(g.proxies).length < 2 || g.type === 'select' ? 'static' : g.type === 'url-test' ? 'url-latency-benchmark' : g.type === 'load-balance' ? 'round-robin' : 'available'}=${quote(g.name)}, ${array(g.proxies).map(quote).join(', ')}`;
    return `${quote(g.name)}=${str(g.type)}, ${array(g.proxies).map(quote).join(', ')}${g.url ? ', url=' + str(g.url) + ', interval=' + str(g.interval, '300') : ''}`;
  }).join('\n');
  const sections = target === 'quanx' ? ['server_local', 'policy', 'filter_local'] : target === 'quan' ? ['SERVER', 'POLICY', 'FILTER'] : target === 'mellow' ? ['Endpoint', 'EndpointGroup', 'RoutingRule'] : ['Proxy', 'Proxy Group', 'Rule'];
  body = replaceSection(base, sections[0], body, true);
  body = replaceSection(body, sections[1], groupLines, true);
  body = replaceSection(body, sections[2], rules.map(r => target === 'quanx' || target === 'quan' ? r.replace(/^DOMAIN-SUFFIX,/, 'HOST-SUFFIX,').replace(/^DOMAIN-KEYWORD,/, 'HOST-KEYWORD,').replace(/^DOMAIN,/, 'HOST,').replace(/^IP-CIDR6,/, 'IP6-CIDR,').replace(/^MATCH,/, 'FINAL,') : r.replace(/^MATCH,/, 'FINAL,')).join('\n'), opts.overwrite);
  if (target === 'surge') for (const n of nodes.filter(n => n.type === 'wireguard')) {
    body += `\n[WireGuard wg_${n.source}_${n.port}_${encodeURIComponent(n.name)}]\nprivate-key=${str(n['private-key'])}\nself-ip=${str(n.ip)}\n${n.ipv6 ? 'self-ip-v6=' + str(n.ipv6) + '\n' : ''}${n['pre-shared-key'] ? 'preshared-key=' + str(n['pre-shared-key']) + '\n' : ''}peer=(public-key=${str(n['public-key'])}, endpoint=${host(n)}:${n.port}, allowed-ips="${array(n['allowed-ips'] ?? ['0.0.0.0/0', '::/0']).join(',')}")\n`;
  }
  return (opts.managed ?? '') + body;
}
export function replaceSection(base: string, section: string, content: string, overwrite: boolean): string {
  const chunks = base.split(/(?=^\[[^\]]+\]\s*$)/m); let found = false;
  const result = chunks.map(chunk => {
    if (!chunk.startsWith(`[${section}]`)) return chunk;
    found = true;
    return `[${section}]\n${overwrite ? '' : chunk.slice(chunk.indexOf('\n') + 1).trim() + '\n'}${content.trim()}\n\n`;
  }).join('');
  return found ? result : result.trimEnd() + `\n\n[${section}]\n${content.trim()}\n`;
}
export function singboxRule(line: string): Dict | undefined {
  const p = line.split(','), type = p.shift()!, noResolve = p.at(-1) === 'no-resolve'; if (noResolve) p.pop();
  const outbound = p.pop(); if (['MATCH', 'FINAL'].includes(type)) return undefined;
  const map: Record<string, string> = { DOMAIN: 'domain', 'DOMAIN-SUFFIX': 'domain_suffix', 'DOMAIN-KEYWORD': 'domain_keyword', 'DOMAIN-REGEX': 'domain_regex', 'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'SRC-IP-CIDR': 'source_ip_cidr', 'DST-PORT': 'port', 'DEST-PORT': 'port', 'SRC-PORT': 'source_port', 'PROCESS-NAME': 'process_name', 'PROCESS-PATH': 'process_path', NETWORK: 'network', GEOIP: 'geoip', GEOSITE: 'geosite' };
  if (!map[type]) throw new HttpError(422, `Unsupported sing-box rule: ${type}`);
  const values = ['port', 'source_port'].includes(map[type]) ? p.map(value => { const port = Number(value); if (!Number.isInteger(port) || port < 1 || port > 65535) throw new HttpError(422, 'Unsupported port rule'); return port; }) : p;
  return { [map[type]]: values.length === 1 ? values[0] : values, outbound };
}
