import { describe, expect, it } from 'vitest';
import { parseLink, parseSubscription } from '../worker/nodes';
import { exportConfig, toClash, toIni, toLink, toSingbox } from '../worker/export';
import { extractUserInfo } from '../worker/userinfo';
import { b64decode, b64encode, regex, safePath } from '../worker/util';
import { parseConfig } from '../worker/config';
import { renderTemplate } from '../worker/template';
import { parseRules, rulesetOutput } from '../worker/rules';
import { makeGroups } from '../worker/convert';

const ss = 'ss://YWVzLTEyOC1nY206dGVzdA==@192.168.100.1:8888#Example1';
const links = [ss,
  'ssr://' + b64encode('example.com:443:auth_sha1_v4:aes-128-cfb:tls1.2_ticket_auth:' + b64encode('p:a:ss', true) + '/?remarks=' + b64encode('香港 SSR', true), true),
  'vmess://' + b64encode(JSON.stringify({ v: '2', ps: '東京', add: 'example.com', port: '443', id: '12345678-abcd-1234-1234-47ffcabcce29', aid: '0', net: 'ws', path: '/v2', host: 'cdn.example.com', tls: 'tls' })),
  'vless://12345678-abcd-1234-1234-47ffcabcce29@[2001:db8::1]:443?security=reality&pbk=public&sid=abcd&sni=example.com&flow=xtls-rprx-vision#Reality',
  'trojan://pass%3Aword@example.com:443?sni=edge.example.com&insecure=1#Trojan',
  'hysteria2://secret@example.com:443?obfs=salamander&obfs-password=hidden&sni=edge.example.com#HY2',
  'tuic://uuid:secret@example.com:443?congestion_control=bbr&alpn=h3#TUIC',
  'anytls://secret@example.com:443?sni=edge.example.com#AnyTLS'
];
describe('protocol fidelity', () => {
  it.each(links)('round-trips link %s', input => {
    const before = parseLink(input), after = parseLink(toLink(before)!);
    expect(after.type).toBe(before.type); expect(after.name).toBe(before.name); expect(after.server).toBe(before.server);
    expect(after.port).toBe(before.port); expect(after.password).toBe(before.password); expect(after.uuid).toBe(before.uuid);
    expect(after['reality-opts']).toEqual(before['reality-opts']);
  });
  it.each(links)('preserves fields through Clash and sing-box %s', input => {
    const before = parseLink(input);
    const clash = parseSubscription(JSON.stringify({ proxies: [toClash(before)] })).nodes[0];
    expect(clash.name).toBe(before.name); expect(clash.password).toBe(before.password);
    const sb = parseSubscription(JSON.stringify({ outbounds: [toSingbox(before)] })).nodes[0];
    expect(sb.type).toBe(before.type); expect(sb.server).toBe(before.server); expect(sb.password).toBe(before.password); expect(sb.uuid).toBe(before.uuid);
    expect(sb['reality-opts']).toEqual(before['reality-opts']);
  });
  it('parses the original README SS example', () => expect(parseLink(ss)).toMatchObject({ type: 'ss', name: 'Example1', server: '192.168.100.1', port: 8888, cipher: 'aes-128-gcm', password: 'test' }));
  it('merges base64 subscriptions and accepts unicode credentials', () => expect(parseSubscription(b64encode(links.join('\n'))).nodes).toHaveLength(links.length));
  it('preserves false flags and wireguard fields', () => {
    const input = { name: 'WG', type: 'wireguard', server: 'example.com', port: 51820, ip: '10.0.0.2/32', 'private-key': 'private', 'public-key': 'public', 'pre-shared-key': 'psk', reserved: [1, 2, 3], udp: false };
    expect(toClash(parseSubscription(JSON.stringify({ proxies: [input] })).nodes[0])).toMatchObject(input);
  });
  it('produces SIP008 and SSD that can be parsed', () => {
    for (const target of ['sssub', 'ssd'] as const) {
      const out = exportConfig(target, [parseLink(ss)], [], [], '', { list: false, version: 3, newFields: true, overwrite: false });
      expect(parseSubscription(out).nodes[0]).toMatchObject({ password: 'test', cipher: 'aes-128-gcm', port: 8888 });
    }
  });
  it.each(['surge', 'surfboard', 'quan', 'quanx', 'loon', 'mellow'] as const)('round-trips SS and VMess through %s full config', target => {
    const opts = { list: false, version: 4, newFields: true, overwrite: true };
    for (const input of [links[0], links[2]]) {
      const n = parseLink(input); const out = exportConfig(target, [n], [], [], '', opts);
      const parsed = parseSubscription(out).nodes[0];
      expect(parsed.type).toBe(n.type); expect(parsed.server).toBe(n.server); expect(parsed.name).toBe(n.name);
      expect(parsed.uuid).toBe(n.uuid); expect(parsed.password).toBe(n.password);
      if (n.network === 'ws') expect(parsed['ws-opts']).toEqual(n['ws-opts']);
    }
  });
  it('uses original Surge 2 module syntax and Mellow endpoint syntax', () => {
    expect(toIni(parseLink(ss), 'surge', 2)).toContain('=custom, 192.168.100.1, 8888, aes-128-gcm, test, https://');
    expect(toIni(parseLink(ss), 'mellow')).toMatch(/^Example1, ss, ss:\/\//);
  });
  it('preserves SS obfs plugin parameters', () => {
    const n = parseLink(ss.replace('#Example1', '/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#Example1'));
    expect(n['plugin-opts']).toEqual({ mode: 'http', host: 'cdn.example.com' });
    expect(parseLink(toLink(n)!)['plugin-opts']).toEqual(n['plugin-opts']);
  });
  it('parses Mieru ranges and Trojan gRPC', () => {
    expect(toClash(parseLink('mierus://user:pass@example.com?port=8000-8100&protocol=TCP#Mieru'))).toMatchObject({ type: 'mieru', username: 'user', password: 'pass', 'port-range': '8000-8100' });
    expect(parseLink('trojan://pass@example.com:443?type=grpc&serviceName=tunnel')).toMatchObject({ network: 'grpc', 'grpc-opts': { 'grpc-service-name': 'tunnel' } });
  });
  it('extracts stream information from remarks before filtering', async () => {
    const cfg = parseConfig('[common]\napi_mode=true\n[userinfo]\nstream_rule=^Used (.*) of (.*)$|used=$1&total=$2');
    const n = parseLink(ss); n.name = 'Used 1GB of 10GB';
    expect(await extractUserInfo([n], cfg, async () => '')).toBe('upload=0; download=1073741824; total=10737418240');
  });
  it('reads Quantumult X wss as TLS and retains Reality parameters', () => {
    const n = parseSubscription('vmess=example.com:443, method=auto, password=uuid, obfs=wss, obfs-host=cdn.example.com, obfs-uri=/ws, tag=QX').nodes[0];
    expect(n.tls).toBe(true); expect(n['ws-opts']).toMatchObject({ path: '/ws', headers: { Host: 'cdn.example.com' } });
    const reality = parseLink(links[3]); const out = toIni(reality, 'quanx');
    expect(parseSubscription(out).nodes[0]['reality-opts']).toEqual(reality['reality-opts']);
  });
  it('emits simple list=true links without base64 and legacy SIP008 arrays', () => {
    const opts = { list: true, version: 4, newFields: true, overwrite: false };
    expect(exportConfig('ss', [parseLink(ss)], [], [], '', opts)).toMatch(/^ss:\/\//);
    expect(Array.isArray(JSON.parse(exportConfig('sssub', [parseLink(ss)], [], [], '', opts)))).toBe(true);
  });
});
describe('declarative configuration', () => {
  it.each(['[common]\napi_mode=true\n[node_pref]\nrename_node=a@b\nrename_node=c@d', 'common:\n  api_mode: true\n', 'version = 1\n[common]\napi_mode = true\ndefault_url = ["https://example.com"]'])('accepts INI/YAML/TOML', text => expect(parseConfig(text).common.api_mode).toBeTruthy());
  it('rejects malformed configuration and scripts', () => {
    expect(() => parseConfig('garbage')).toThrow(); expect(() => parseConfig('[common]\nfilter_script=function filter() {}')).toThrow(/JavaScript/);
    expect(() => parseConfig('tasks:\n  - name: script')).toThrow(/cron/);
  });
  it('renders nested conditions, loops, helper calls and includes', async () => {
    const output = await renderTemplate('{% if default(request.missing, "yes") == "yes" %}{% for n in range(3) %}{{ n }}{% endfor %}{% include "base/part.tpl" %}{% else %}bad{% endif %}', { request: {} }, async () => '{{ replace("ABC", "(?i)a", "X") }}');
    expect(output).toBe('012XBC');
  });
  it('does not evaluate fetch in unselected branches', async () => expect(await renderTemplate('{% if false %}{{ fetch("bad") }}{% else %}ok{% endif %}', {}, async () => { throw new Error(); })).toBe('ok'));
  it('rejects recursion, arbitrary functions, prototype access and malformed template', async () => {
    await expect(renderTemplate('{% include "base/a" %}', {}, async () => '{% include "base/a" %}')).rejects.toThrow(/Recursive/);
    await expect(renderTemplate('{{ request.constructor }}', { request: {} }, async () => '')).rejects.toThrow();
    await expect(renderTemplate('{{ eval("1") }}', {}, async () => '')).rejects.toThrow();
    await expect(renderTemplate('{% if true %}oops', {}, async () => '')).rejects.toThrow();
  });
  it('supports PCRE leading flags and rejects unsupported/unsafe patterns', () => {
    expect(regex('(?i)hk').test('HK')).toBe(true); expect(() => regex('(a+)+')).toThrow(); expect(() => regex('(?R)')).toThrow();
  });
  it('enforces resource boundaries', () => {
    for (const p of ['../pref.ini', '%2e%2e/pref.ini', 'C:/secret', 'base\\secret']) expect(() => safePath(p)).toThrow();
    expect(() => safePath('base-other/file', 'base')).toThrow();
  });
  it('filters by source group and rejects cyclic groups', () => {
    expect(makeGroups(['G`select`!!GROUPID=0'], [parseLink(ss)])[0].proxies).toEqual(['Example1']);
    expect(() => makeGroups(['A`select`[]B', 'B`select`[]A'], [parseLink(ss)])).toThrow(/Cyclic/);
  });
  it('converts all six ruleset formats with policy ordering', () => {
    const rules = parseRules('DOMAIN,example.com\nDOMAIN-SUFFIX,example.org\nIP-CIDR,10.0.0.0/8,no-resolve');
    for (let type = 1; type <= 6; type++) expect(rulesetOutput(rules, type, 'Proxy').length).toBeGreaterThan(0);
    expect(rulesetOutput(rules, 2, 'Proxy')).toContain('IP-CIDR,10.0.0.0/8,Proxy,no-resolve');
    expect(rulesetOutput(rules, 3, '')).toContain('+.example.org');
    expect(rulesetOutput(rules, 5, '')).toContain('.example.org');
  });
});
