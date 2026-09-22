import { parse as yamlParse } from 'yaml';
import { parse as tomlParse } from 'smol-toml';
import { array, bool, Dict, HttpError, integer, lines, record, regex, str } from './util';

export type Ini = Record<string, Record<string, string[]>>;
export function parseIni(text: string, loose = false): Ini {
  const result: Ini = Object.create(null); let section = '';
  for (const line of lines(text)) {
    const match = /^\[([^\]]+)\]$/.exec(line);
    if (match) { section = match[1]; result[section] ??= Object.create(null); continue; }
    const at = line.indexOf('=');
    if (at < 0) { if (loose) { result[section] ??= Object.create(null); (result[section]['__lines'] ??= []).push(line); continue; }
      throw new HttpError(400, 'Invalid INI configuration'); }
    if (!section) throw new HttpError(400, 'Missing INI section');
    const key = line.slice(0, at).trim(), value = line.slice(at + 1).trim();
    (result[section][key] ??= []).push(value);
  }
  return result;
}
export interface Config {
  common: Dict; node_pref: Dict; managed_config: Dict; emojis: Dict; rulesets: Dict;
  proxy_groups: Dict; template: Dict; advanced: Dict; userinfo: Dict; aliases: Dict;
  [key: string]: Dict;
}
export function parseConfig(text: string): Config {
  if (!text.trim()) throw new HttpError(400, 'Empty configuration');
  let raw: Dict;
  try {
    if (/^\s*(?:version\s*=|\[\[)/m.test(text) || /^\s*\[[^\]]+\][\s\S]*?^\s*\w+\s*=\s*(?:["']|\[)/m.test(text)) {
      try { raw = tomlParse(text) as Dict; } catch { raw = iniObject(parseIni(text)); }
    } else if (/^\s*\[/.test(text)) raw = iniObject(parseIni(text));
    else { const doc: unknown = yamlParse(text, { maxAliasCount: 50 });
      if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error(); raw = record(doc); }
  } catch (e) { if (e instanceof HttpError) throw e; throw new HttpError(400, 'Invalid configuration'); }
  const cfg: Config = { common: {}, node_pref: {}, managed_config: {}, emojis: {}, rulesets: {}, proxy_groups: {}, template: {}, advanced: {}, userinfo: {}, aliases: {} };
  if (!Object.keys(raw).some(k => Object.hasOwn(cfg, k) || k === 'custom' || k === 'tasks')) throw new HttpError(400, 'No recognized configuration sections');
  for (const key of Object.keys(cfg)) cfg[key] = record(raw[key]);
  if (Array.isArray(raw.aliases)) cfg.aliases = Object.fromEntries(raw.aliases.map(v => [str(record(v).uri), record(v).target]));
  if (Object.keys(record(raw.custom)).length) cfg.custom = record(raw.custom);
  if (Array.isArray(raw.tasks) && raw.tasks.length || Object.keys(record(raw.tasks)).length)
    throw new HttpError(422, 'Script cron tasks are not supported');
  validateScripts(raw);
  if (bool(cfg.common.enable_filter)) throw new HttpError(422, 'JavaScript filters are not supported');
  for (const key of ['proxy_config', 'proxy_subscription', 'proxy_ruleset']) {
    const proxy = str(cfg.common[key]);
    if (proxy && proxy !== 'NONE' && proxy !== 'SYSTEM') throw new HttpError(422, 'Outbound proxy settings are not supported');
  }
  for (const key of ['cache_subscription', 'cache_config', 'cache_ruleset', 'max_allowed_rules', 'max_allowed_download_size', 'max_allowed_rulesets']) if (cfg.advanced[key] !== undefined) integer(cfg.advanced[key], 0);
  if (cfg.managed_config.config_update_interval !== undefined) integer(cfg.managed_config.config_update_interval, 86400);
  for (const key of ['include_remarks', 'exclude_remarks']) for (const value of array(cfg.common[key])) if (value) regex(str(value));
  return cfg;
}
function iniObject(ini: Ini): Dict {
  return Object.fromEntries(Object.entries(ini).map(([section, values]) => [section, Object.fromEntries(Object.entries(values).map(([k, v]) => [k, v.length === 1 ? v[0] : v]))]));
}
export function validateScripts(value: unknown, key = ''): void {
  if (typeof value === 'string' && (/(?:^|!!)script:/.test(value) || ['filter_script', 'sort_script', 'script'].includes(key) && value && value !== 'false'))
    throw new HttpError(422, 'Custom JavaScript execution is not supported');
  if (Array.isArray(value)) value.forEach(v => validateScripts(v, key));
  else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) validateScripts(v, k);
}
export type Loader = (path: string, kind?: 'config' | 'ruleset' | 'subscription') => Promise<string>;
export async function expandEntries(value: unknown, load: Loader, kind = '', stack: string[] = []): Promise<string[]> {
  const result: string[] = [];
  for (const entry of array(value)) {
    const obj = record(entry), text = typeof entry === 'string' ? entry : '';
    const imported = str(obj.import) || (text.startsWith('!!import:') ? text.slice(9) : '');
    if (imported) {
      if (stack.includes(imported) || stack.length >= 8) throw new HttpError(400, 'Recursive resource import');
      result.push(...await expandEntries(lines(await load(imported)), load, kind, [...stack, imported]));
    } else if (text) result.push(text);
    else if (kind === 'rename') result.push(`${str(obj.match)}@${str(obj.replace)}`);
    else if (kind === 'emoji') result.push(`${str(obj.match)},${str(obj.emoji)}`);
    else if (kind === 'ruleset') result.push(`${str(obj.group)},${obj.rule ? '[]' + str(obj.rule) : str(obj.ruleset)},${str(obj.interval)}`);
    else if (kind === 'group') result.push('@json:' + JSON.stringify(obj));
    else if (kind === 'userinfo') result.push(`${str(obj.match)}|${str(obj.replace)}`);
  }
  validateScripts(result);
  return result;
}
export function customConfig(base: Config, external: Config): Config {
  const out = structuredClone(base), c = external.custom ?? {};
  for (const [key, value] of Object.entries(c)) {
    if (key.endsWith('_rule_base') || ['include_remarks', 'exclude_remarks'].includes(key)) out.common[key] = value;
    else if (key === 'custom_proxy_group' || key === 'proxy_groups') out.proxy_groups.custom_proxy_group = value;
    else if (key === 'ruleset' || key === 'rulesets') out.rulesets.rulesets = value;
    else if (key === 'enable_rule_generator') out.rulesets.enabled = value;
    else if (key === 'overwrite_original_rules') out.rulesets.overwrite_original_rules = value;
    else if (['add_emoji', 'remove_old_emoji'].includes(key)) out.emojis[key] = value;
    else if (key === 'emojis' || key === 'emoji') out.emojis.rules = value;
    else if (key === 'template_args') out.template.locals = value;
    else out.node_pref[key] = value;
  }
  return out;
}
export function listValue(cfg: Dict, plural: string, singular: string): unknown { return cfg[plural] ?? cfg[singular]; }
