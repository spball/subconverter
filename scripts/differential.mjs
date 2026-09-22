// Run identical sanitized requests against an original binary and a local Worker.
// Usage: node scripts/differential.mjs http://127.0.0.1:25500 http://127.0.0.1:8787
import { parse } from 'yaml';
import { mkdir, writeFile } from 'node:fs/promises';
const [original, worker] = process.argv.slice(2);
if (!original || !worker) throw new Error('Pass original and Worker base URLs. Neither endpoint may be a production service.');
const fixture = 'ss://YWVzLTEyOC1nY206dGVzdA==@192.168.100.1:8888#Example1';
const results = [];
function stable(v) { return Array.isArray(v) ? v.map(stable) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, stable(v[k])])) : v; }
for (const target of ['clash', 'clashr', 'ss', 'sssub', 'surge', 'quan', 'quanx', 'loon', 'mellow', 'singbox']) {
  const query = '/sub?' + new URLSearchParams({ target, url: fixture, list: 'true', emoji: 'false', remove_emoji: 'false', insert: 'false', ver: '4' });
  const responses = await Promise.all([original, worker].map(async base => {
    const res = await fetch(base.replace(/\/$/, '') + query); return { status: res.status, body: await res.text() };
  }));
  const normalize = body => ['clash', 'clashr'].includes(target) ? JSON.stringify(stable(parse(body))) : ['sssub', 'singbox'].includes(target) ? JSON.stringify(stable(JSON.parse(body))) : body;
  let equal = false;
  try { equal = responses[0].status === responses[1].status && normalize(responses[0].body) === normalize(responses[1].body); } catch { /* retain mismatch */ }
  results.push({ target, equal, original: responses[0], worker: responses[1] });
}
await mkdir('.baseline-build', { recursive: true });
await writeFile('.baseline-build/differential.json', JSON.stringify(results, null, 2));
console.table(results.map(({ target, equal }) => ({ target, equal })));
if (results.some(r => !r.equal)) process.exitCode = 1;
