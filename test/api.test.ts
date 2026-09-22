import { env, createExecutionContext, waitOnExecutionContext, runInDurableObject } from 'cloudflare:test';
import { fetchMock } from './network';
import { beforeEach, afterEach, describe, expect, it } from 'vitest';
import worker from '../worker/index';
import { b64encode } from '../worker/util';
import { parse as yamlParse } from 'yaml';
import contract from './fixtures/legacy-contract.json';

declare module 'cloudflare:test' { interface ProvidedEnv extends Env {} }
const ss = 'ss://YWVzLTEyOC1nY206dGVzdA==@192.168.100.1:8888#Example1';
async function call(path: string, init?: RequestInit): Promise<Response> {
  const ctx = createExecutionContext(); const response = await worker.fetch(new Request('https://worker.example' + path, init), env, ctx);
  await waitOnExecutionContext(ctx); return response;
}
const sub = (target = 'clash', extras = '') => '/sub?' + new URLSearchParams({ target, url: ss }) + extras;
beforeEach(async () => {
  fetchMock.activate(); fetchMock.disableNetConnect();
  await runInDurableObject(env.CONFIG.getByName('global'), async (_instance, state) => { await state.storage.deleteAll(); });
});
afterEach(() => { fetchMock.assertNoPendingInterceptors(); fetchMock.deactivate(); });
describe('HTTP contract', () => {
  it.each(['clash', 'clashr', 'surge', 'surfboard', 'quan', 'quanx', 'loon', 'mellow', 'singbox', 'ss', 'sssub', 'ssd', 'mixed'])('converts SS to %s', async target => {
    const res = await call(sub(target)); expect(res.status, await res.clone().text()).toBe(200); expect((await res.text()).length).toBeGreaterThan(10);
  });
  it('preserves README example and download headers', async () => {
    const res = await call(sub('clash', '&filename=test.yaml&interval=7200'));
    expect(res.headers.get('Content-Disposition')).toContain('test.yaml'); expect(res.headers.get('profile-update-interval')).toBe('2');
    expect(yamlParse(await res.text()).proxies[0]).toMatchObject({ name: 'Example1', server: '192.168.100.1', password: 'test' });
  });
  it('returns HEAD metadata without body', async () => { const res = await call(sub(), { method: 'HEAD' }); expect(res.status).toBe(200); expect(await res.text()).toBe(''); });
  it('detects target from User-Agent', async () => { const res = await call(sub('auto'), { headers: { 'User-Agent': 'Clash/1.0' } }); expect(res.status).toBe(200); expect(await res.text()).toContain('proxies:'); });
  it('supports legacy convenience route', async () => { const res = await call('/sub2clashr?sublink=' + encodeURIComponent(ss)); expect(res.status).toBe(200); });
  it('rejects missing targets and unsupported scripts', async () => {
    expect((await call('/sub')).status).toBe(400); expect((await call(sub('nope'))).status).toBe(400);
    expect((await call(sub('clash', '&filter_script=test'))).status).toBe(422);
    expect((await call(sub(), { method: 'POST' })).status).toBe(405);
  });
  it('does not serve private assets directly', async () => { for (const path of ['/pref.ini', '/base/all_base.tpl', '/getlocal?path=pref.ini', '/get?url=https://example.com']) expect((await call(path)).status).toBe(404); });
  it('renders bundled template and enforces its scope', async () => {
    const good = await call('/render?path=base/all_base.tpl&target=clash'); expect(good.status, await good.clone().text()).toBe(200);
    expect((await call('/render?path=pref.ini')).status).toBe(404);
  });
  it('requires administrator auth and retains valid config after failed update', async () => {
    expect((await call('/flushcache')).status).toBe(403);
    expect((await call('/updateconf?type=direct', { method: 'POST', body: '[common]\napi_mode=true' })).status).toBe(403);
    const update = await call('/updateconf?type=direct&token=test-secret', { method: 'POST', body: '[common]\napi_mode=true\n[node_pref]\nrename_node=Example@Test' }); expect(update.status).toBe(200);
    expect(await (await call(sub())).text()).toContain('Test');
    expect((await call('/updateconf?type=direct&token=test-secret', { method: 'POST', body: 'bad' })).status).toBe(400);
    expect(await (await call(sub())).text()).toContain('Test');
    expect((await call('/readconf?token=test-secret')).status).toBe(200);
  });
  it('does not authorize admin when token is unconfigured', async () => {
    const ctx = createExecutionContext(); const res = await worker.fetch(new Request('https://worker.example/flushcache'), { ...env, ACCESS_TOKEN: undefined }, ctx);
    expect(res.status).toBe(403); await waitOnExecutionContext(ctx);
  });
  it('flushes resource caches across requests', async () => {
    const pool = fetchMock.get('https://provider.example'); const path = '/sub?' + new URLSearchParams({ target: 'ss', url: 'https://provider.example/sub' });
    pool.intercept({ path: '/sub' }).reply(200, ss, { headers: { 'Subscription-UserInfo': 'upload=1; download=2; total=3' } });
    const first = await call(path); expect(first.status).toBe(200); expect(first.headers.get('Subscription-UserInfo')).toContain('total=3');
    expect((await call(path)).status).toBe(200);
    expect((await call('/flushcache?token=test-secret')).status).toBe(200);
    pool.intercept({ path: '/sub' }).reply(200, ss.replace('#Example1', '#Changed'));
    expect((await call(path)).status).toBe(200);
  });
  it('converts remote rulesets and refreshes rules', async () => {
    fetchMock.get('https://rules.example').intercept({ path: '/list' }).reply(200, 'DOMAIN,example.com\nIP-CIDR,10.0.0.0/8,no-resolve');
    const res = await call('/getruleset?type=2&url=' + b64encode('https://rules.example/list', true) + '&group=' + b64encode('Proxy', true));
    expect(res.status).toBe(200); expect(await res.text()).toContain('IP-CIDR,10.0.0.0/8,Proxy,no-resolve');
    expect((await call('/refreshrules?token=test-secret')).status).toBe(200);
  });
  it('preserves source rules and groups in surge2clash', async () => {
    fetchMock.get('https://provider.example').intercept({ path: '/surge' }).reply(200, '[Proxy]\nNode=ss, example.com, 443, encrypt-method=aes-128-gcm, password=secret\n[Proxy Group]\nSelect=select, Node, DIRECT\n[Rule]\nDOMAIN,example.org,Select\nFINAL,DIRECT');
    const res = await call('/surge2clash?link=' + encodeURIComponent('https://provider.example/surge'));
    expect(res.status, await res.clone().text()).toBe(200); const d = yamlParse(await res.text()); expect(d['proxy-groups'][0].name).toBe('Select'); expect(d.rules).toContain('DOMAIN,example.org,Select');
  });
  it('reports upstream failure', async () => { fetchMock.get('https://provider.example').intercept({ path: '/fail' }).reply(500, 'private detail'); const res = await call('/sub?' + new URLSearchParams({ target: 'ss', url: 'https://provider.example/fail' })); expect(res.status).toBe(502); expect(await res.text()).not.toContain('private detail'); });
  it('isolates concurrent request mutations', async () => {
    const [a, b] = await Promise.all([call(sub('clash', '&rename=Example1%40A')), call(sub('clash', '&rename=Example1%40B'))]);
    expect(yamlParse(await a.text()).proxies[0].name).toBe('A'); expect(yamlParse(await b.text()).proxies[0].name).toBe('B');
  });
  it('uses exact legacy response text where applicable', async () => {
    expect(await (await call('/sub?target=invalid')).text()).toBe(contract.errors.invalidTarget);
    expect(await (await call('/sub?target=ss')).text()).toBe(contract.errors.invalidRequest);
    expect(await (await call('/flushcache?token=test-secret')).text()).toBe(contract.success.flushcache);
    expect(await (await call('/refreshrules?token=test-secret')).text()).toBe(contract.success.refreshrules);
    expect(await (await call('/updateconf?token=test-secret&type=unknown', { method: 'POST' })).text()).toBe(contract.errors.unsupportedUpdateType);
  });
  it('loads a single profile with its own token and merges multiple profiles with admin token', async () => {
    const single = await call('/getprofile?name=profiles/example_profile.ini&token=CHANGE_ME_EXAMPLE_ONLY');
    expect(single.status, await single.clone().text()).toBe(200); expect(yamlParse(await single.text()).proxies[0].name).toBe('Profile');
    expect((await call('/getprofile?name=profiles/example_profile.ini&token=wrong')).status).toBe(403);
    expect((await call('/getprofile?name=profiles/example_profile.ini|profiles/example_second.ini&token=CHANGE_ME_EXAMPLE_ONLY')).status).toBe(403);
    const multiple = await call('/getprofile?name=profiles/example_profile.ini|profiles/example_second.ini&token=test-secret');
    expect(multiple.status).toBe(200); expect(yamlParse(await multiple.text()).proxies).toHaveLength(2);
    expect((await call('/getprofile?name=profiles/missing.ini&token=test-secret')).status).toBe(404);
  });
  it('enables conditional local/get routes and aliases through configuration', async () => {
    await call('/updateconf?type=direct&token=test-secret', { method: 'POST', body: '[common]\napi_mode=false\n[aliases]\n/v=/version' });
    const alias = await call('/v'); expect(alias.status).toBe(302); expect(alias.headers.get('Location')).toBe('/version');
    expect((await call('/getlocal?path=rules/LocalAreaNetwork.list')).status).toBe(200);
    expect((await call('/getlocal?path=../LICENSE')).status).toBe(400);
    fetchMock.get('https://resource.example').intercept({ path: '/hello' }).reply(200, 'hello');
    expect(await (await call('/get?url=https://resource.example/hello')).text()).toBe('hello');
  });
  it('updates and creates Gists only with admin authorization (mocked)', async () => {
    expect((await call(sub('ss', '&upload=true'))).status).toBe(403);
    fetchMock.get('https://api.github.com').intercept({ path: '/gists', method: 'POST' }).reply(201, '{"id":"fixture-gist"}');
    expect((await call(sub('ss', '&upload=true&token=test-secret'))).status).toBe(200);
    fetchMock.get('https://api.github.com').intercept({ path: '/gists/fixture-gist', method: 'PATCH' }).reply(200, '{"id":"fixture-gist"}');
    expect((await call(sub('ss', '&upload=true&token=test-secret'))).status).toBe(200);
  });
  it('returns explicit failures for malformed subscriptions and oversized upstream data', async () => {
    fetchMock.get('https://provider.example').intercept({ path: '/invalid' }).reply(200, '{"proxies": broken}');
    expect((await call('/sub?' + new URLSearchParams({ target: 'clash', url: 'https://provider.example/invalid' }))).status).toBe(400);
    fetchMock.get('https://provider.example').intercept({ path: '/large' }).reply(200, 'x', { headers: { 'Content-Length': '3000000' } });
    expect((await call('/sub?' + new URLSearchParams({ target: 'clash', url: 'https://provider.example/large' }))).status).toBe(413);
  });
  it('follows redirects with a bounded request budget', async () => {
    fetchMock.get('https://provider.example').intercept({ path: '/redirect' }).reply(302, '', { headers: { Location: '/final' } });
    fetchMock.get('https://provider.example').intercept({ path: '/final' }).reply(200, ss);
    expect((await call('/sub?' + new URLSearchParams({ target: 'ss', url: 'https://provider.example/redirect' }))).status).toBe(200);
  });
  it('supports every ruleset output type and validates inputs', async () => {
    for (let type = 1; type <= 6; type++) {
      const res = await call('/getruleset?type=' + type + '&url=' + b64encode('rules/LocalAreaNetwork.list', true) + '&group=' + b64encode('DIRECT', true));
      expect(res.status).toBe(200); expect(await res.text()).not.toBe('');
    }
    expect((await call('/getruleset?type=7')).status).toBe(400);
    expect((await call('/getruleset?type=2&url=' + b64encode('rules/LocalAreaNetwork.list', true))).status).toBe(400);
  });
  it('supports remote provider output and declarative client script generation', async () => {
    const custom = '[custom]\ncustom_proxy_group=Proxy`select`.*\nruleset=Proxy,https://rules.example/list\nruleset=DIRECT,[]FINAL';
    fetchMock.get('https://config.example').intercept({ path: '/custom' }).reply(200, custom);
    const res = await call(sub('clash', '&config=https://config.example/custom&expand=false&classic=true&script=true'));
    expect(res.status, await res.clone().text()).toBe(200);
    const parsed = yamlParse(await res.text()); expect(parsed['rule-providers'].ruleset_0.url).toContain('/getruleset?type=6');
    expect(parsed.script.code).toContain('ctx.rule_providers');
  });
  it('retains persisted configuration after object eviction', async () => {
    const { evictDurableObject } = await import('cloudflare:test');
    await call('/updateconf?type=direct&token=test-secret', { method: 'POST', body: '[common]\napi_mode=true\n[node_pref]\nrename_node=Example1@Persisted' });
    await evictDurableObject(env.CONFIG.getByName('global'));
    expect(yamlParse(await (await call(sub())).text()).proxies[0].name).toBe('Persisted');
  });
  it('splits non-classical providers into domain and CIDR categories', async () => {
    fetchMock.get('https://config.example').intercept({ path: '/split' }).reply(200, '[custom]\nruleset=Proxy,https://rules.example/split');
    fetchMock.get('https://rules.example').intercept({ path: '/split' }).reply(200, 'DOMAIN-SUFFIX,example.org\nIP-CIDR,10.0.0.0/8');
    const res = await call(sub('clash', '&config=https://config.example/split&expand=false'));
    expect(res.status, await res.clone().text()).toBe(200); const config = yamlParse(await res.text());
    expect(config['rule-providers'].ruleset_0_domain.behavior).toBe('domain');
    expect(config['rule-providers'].ruleset_0_ipcidr.url).toContain('type=4');
  });
  it('preserves structured Clash provider group properties', async () => {
    fetchMock.get('https://config.example').intercept({ path: '/providers' }).reply(200, 'custom:\n  proxy_groups:\n    - name: Auto\n      type: url-test\n      url: https://example.com/ping\n      interval: 300\n      use: [provider]\n      lazy: true\n      extra: {icon: https://example.com/icon.png}');
    const res = await call(sub('clash', '&config=https://config.example/providers'));
    expect(res.status, await res.clone().text()).toBe(200); const group = yamlParse(await res.text())['proxy-groups'][0];
    expect(group).toMatchObject({ name: 'Auto', use: ['provider'], lazy: true, icon: 'https://example.com/icon.png' });
  });
});
