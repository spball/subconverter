import { build } from 'esbuild';
import { mkdir, writeFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

await mkdir('.bench', { recursive: true });
await build({ entryPoints: ['worker/nodes.ts', 'worker/export.ts', 'worker/rules.ts'], outdir: '.bench', bundle: true, packages: 'external', platform: 'node', format: 'esm', outExtension: { '.js': '.mjs' } });
const { parseSubscription } = await import(pathToFileURL(resolve('.bench/nodes.mjs')).href);
const { exportConfig } = await import(pathToFileURL(resolve('.bench/export.mjs')).href);
const { parseRules, rulesetOutput } = await import(pathToFileURL(resolve('.bench/rules.mjs')).href);
const results = [];
for (const [count, ruleCount] of [[20, 100], [200, 2000], [1000, 10000]]) {
  const source = Array.from({ length: count }, (_, i) => `ss://YWVzLTEyOC1nY206dGVzdA@example.com:443#Node${i}`).join('\n');
  const ruleSource = Array.from({ length: ruleCount }, (_, i) => `DOMAIN-SUFFIX,domain${i}.example.com`).join('\n');
  for (const target of ['clash', 'singbox', 'mixed']) {
    const times = []; let bytes = 0;
    for (let run = 0; run < 12; run++) {
      const start = performance.now();
      const { nodes } = parseSubscription(source);
      const rules = parseRules(ruleSource);
      const result = exportConfig(target, nodes, [{ name: 'Proxy', type: 'select', proxies: nodes.map(n => n.name) }], rules.map(r => r + ',Proxy'), '', { list: false, version: 4, newFields: true, overwrite: true });
      rulesetOutput(rules, 6, ''); bytes = Buffer.byteLength(result);
      if (run >= 2) times.push(performance.now() - start);
    }
    times.sort((a, b) => a - b);
    results.push({ nodes: count, rules: ruleCount, target, medianMs: +times[5].toFixed(2), p90Ms: +times[8].toFixed(2), outputBytes: bytes });
  }
}
const report = { measuredAt: new Date().toISOString(), node: process.version, platform: process.platform,
  note: 'Local Node.js CPU-path timings, including YAML provider serialization. Excludes network, templates, Durable Object and Workers overhead; not a guarantee of Cloudflare Free CPU compliance.', results };
console.table(results);
await writeFile('docs/benchmark.json', JSON.stringify(report, null, 2) + '\n');
