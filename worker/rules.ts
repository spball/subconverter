import { parse as yamlParse, stringify as yamlStringify } from 'yaml';
import { Loader } from './config';
import { array, b64encode, csv, Dict, HttpError, integer, lines, record, str } from './util';
export function parseRules(text: string, type = 'surge'): string[] {
  const input = type.startsWith('clash-') ? array(record(yamlParse(text, { maxAliasCount: 50 })).payload).map(v => str(v)) : lines(text);
  return input.filter(s => s && !/^(#|;|\/\/)/.test(s)).map(s => {
    if (type === 'clash-domain' || type === 'domain-set') return (s.startsWith('+.') ? 'DOMAIN-SUFFIX,' + s.slice(2) : s.startsWith('.') ? 'DOMAIN-SUFFIX,' + s.slice(1) : 'DOMAIN,' + s);
    if (type === 'clash-ipcidr') return (s.includes(':') ? 'IP-CIDR6,' : 'IP-CIDR,') + s;
    const p = csv(s); p[0] = p[0].toUpperCase();
    p[0] = ({ HOST: 'DOMAIN', 'HOST-SUFFIX': 'DOMAIN-SUFFIX', 'HOST-KEYWORD': 'DOMAIN-KEYWORD', 'IP6-CIDR': 'IP-CIDR6', FINAL: 'MATCH' } as Record<string, string>)[p[0]] ?? p[0];
    const extra = p.includes('no-resolve') ? ',no-resolve' : '';
    if (['MATCH', 'FINAL'].includes(p[0])) return 'MATCH';
    if (p.length < 2) throw new HttpError(400, 'Invalid rule');
    return p.slice(0, 2).join(',') + extra;
  });
}
export function typedPath(s: string): [string, string] {
  const m = /^(surge|quanx|clash-domain|clash-ipcidr|clash-classic|domain-set):(.*)$/.exec(s);
  return m ? [m[1], m[2]] : ['surge', s];
}
export async function readRules(path: string, load: Loader): Promise<string[]> {
  const [type, url] = typedPath(path); return parseRules(await load(url, 'ruleset'), type);
}
export function attachPolicy(rule: string, group: string): string {
  return rule.endsWith(',no-resolve') ? rule.slice(0, -11) + ',' + group + ',no-resolve' : rule + ',' + group;
}
export function rulesetOutput(rules: string[], type: number, group: string): string {
  if (type < 1 || type > 6 || type === 2 && !group) throw new HttpError(400, 'Invalid request!');
  if (type === 3 || type === 5) {
    const domains = rules.filter(r => /^DOMAIN(?:-SUFFIX)?,/.test(r)).map(r => (r.startsWith('DOMAIN-SUFFIX,') ? type === 3 ? '+.' : '.' : '') + csv(r)[1]);
    return type === 3 ? yamlStringify({ payload: domains }) : domains.join('\n') + (domains.length ? '\n' : '');
  }
  if (type === 4) return yamlStringify({ payload: rules.filter(r => /^IP-CIDR6?,/.test(r)).map(r => csv(r)[1]) });
  if (type === 6) return yamlStringify({ payload: rules });
  return rules.map(r => type === 2 ? attachPolicy(r.replace(/^IP-CIDR6,/, 'IP6-CIDR,').replace(/^MATCH$/, 'FINAL'), group) : r.replace(/^MATCH$/, 'FINAL')).join('\n') + '\n';
}
export async function buildRules(entries: string[], load: Loader, opts: { target: string; expand: boolean; classic: boolean; prefix: string; maxRules?: number }): Promise<{ rules: string[]; providers: Dict }> {
  const rules: string[] = [], providers: Dict = {};
  if (entries.length > 32) throw new HttpError(422, 'Ruleset limit exceeded (32)');
  for (const [index, entry] of entries.entries()) {
    const comma = entry.indexOf(','); if (comma < 1) throw new HttpError(400, 'Invalid ruleset entry');
    const group = entry.slice(0, comma), remainder = entry.slice(comma + 1);
    if (remainder.startsWith('[]')) { rules.push(attachPolicy(parseRules(remainder.slice(2))[0], group)); continue; }
    const [path, ttl] = csv(remainder); if (!path) throw new HttpError(400, 'Missing ruleset path');
    const url = `${opts.prefix}/getruleset?type=${opts.target === 'quanx' ? 2 : opts.classic ? 6 : 1}&url=${b64encode(path, true)}${opts.target === 'quanx' ? '&group=' + b64encode(group, true) : ''}`;
    if (!opts.expand && ['clash', 'clashr'].includes(opts.target)) {
      const name = 'ruleset_' + index;
      if (opts.classic) {
        providers[name] = { type: 'http', behavior: 'classical', url: url.replace(/type=\d/, 'type=6'), path: `./ruleset/${name}.yaml`, interval: integer(ttl, 86400) };
        rules.push(`RULE-SET,${name},${group}`);
      } else {
        const contents = await readRules(path, load);
        for (const [suffix, pattern, behavior, type] of [['domain', /^DOMAIN(?:-SUFFIX)?,/, 'domain', 3], ['ipcidr', /^IP-CIDR6?,/, 'ipcidr', 4]] as const) {
          if (contents.some(r => pattern.test(r))) {
            const provider = name + '_' + suffix;
            providers[provider] = { type: 'http', behavior, url: url.replace(/type=\d/, 'type=' + type), path: `./ruleset/${provider}.yaml`, interval: integer(ttl, 86400) };
            rules.push(`RULE-SET,${provider},${group}`);
          }
        }
        rules.push(...contents.filter(r => !/^(DOMAIN(?:-SUFFIX)?|IP-CIDR6?),/.test(r)).map(r => attachPolicy(r, group)));
      }
    } else if (!opts.expand && ['surge', 'surfboard', 'loon'].includes(opts.target)) rules.push(`RULE-SET,${url},${group}`);
    else rules.push(...(await readRules(path, load)).map(r => attachPolicy(r, group)));
    if (rules.length > (opts.maxRules && opts.maxRules > 0 ? Math.min(20000, opts.maxRules) : 20000)) throw new HttpError(413, 'Rule limit exceeded');
  }
  return { rules, providers };
}
