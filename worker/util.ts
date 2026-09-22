export class HttpError extends Error {
  constructor(public status: number, message: string) { super(message); }
}
export type Dict = Record<string, unknown>;
export const record = (v: unknown): Dict => v !== null && typeof v === 'object' && !Array.isArray(v) ? v as Dict : {};
export const str = (v: unknown, fallback = ''): string => v === undefined || v === null ? fallback : String(v);
export const array = (v: unknown): unknown[] => v === undefined || v === null ? [] : Array.isArray(v) ? v : [v];
export const bool = (v: unknown, fallback = false): boolean => v === undefined || v === null || v === '' ? fallback : v === true || v === 1 || v === 'true' || v === '1';
export function integer(v: unknown, fallback: number, min = 0, max = Number.MAX_SAFE_INTEGER): number {
  if (v === undefined || v === null || v === '') return fallback;
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < min || n > max) throw new HttpError(400, 'Invalid numeric value');
  return n;
}
export function b64decode(s: string): string {
  try {
    s = s.replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/');
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(Uint8Array.from(atob(s.padEnd(Math.ceil(s.length / 4) * 4, '=')), c => c.charCodeAt(0)));
  } catch { throw new HttpError(400, 'Invalid Base64 encoding'); }
}
export function b64encode(s: string, safe = false): string {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 8192) bin += String.fromCharCode(...bytes.subarray(i, i + 8192));
  const result = btoa(bin);
  return safe ? result.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : result;
}
export function decode(s: string): string {
  try { return decodeURIComponent(s); } catch { throw new HttpError(400, 'Invalid URL encoding'); }
}
export function regex(source: string, global = false): RegExp {
  let flags = global ? 'g' : '';
  source = source.replace(/^\(\?([ims]+)\)/, (_, f: string) => { flags += f; return ''; });
  // PCRE branch reset, recursion, conditionals, atomic groups and possessive quantifiers are not JS regex.
  if (source.length > 2048 || /\(\?(?:>|\||R|\(|\d)|\\[KRC]|[+*?]\+|\{\d+(?:,\d*)?\}\+/.test(source))
    throw new HttpError(400, 'Unsupported or oversized PCRE expression');
  // Reject common exponential backtracking forms before entering the runtime regex engine.
  if (/\([^)]*[+*][^)]*\)[+*{]/.test(source)) throw new HttpError(400, 'Unsafe nested regex quantifier');
  try { return new RegExp(source, [...new Set(flags)].join('')); }
  catch { throw new HttpError(400, 'Invalid or unsupported regular expression'); }
}
export function lines(s: string): string[] { return s.replace(/^\uFEFF/, '').split(/\r?\n|\r/).map(s => s.trim()).filter(s => s && !/^(#|;|\/\/)/.test(s)); }
export function csv(s: string): string[] {
  const parts: string[] = []; let value = '', quote = '', depth = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) { value += c; if (c === quote && s[i - 1] !== '\\') quote = ''; }
    else if (c === '"' || c === "'") { quote = c; value += c; }
    else if (c === '(') { depth++; value += c; }
    else if (c === ')') { depth--; value += c; }
    else if (c === ',' && depth === 0) { parts.push(value.trim()); value = ''; }
    else value += c;
  }
  parts.push(value.trim());
  return parts.map(p => /^(["']).*\1$/.test(p) ? p.slice(1, -1) : p);
}
export function splitOnce(s: string, sep: string): [string, string] {
  const at = s.indexOf(sep); return at < 0 ? [s, ''] : [s.slice(0, at), s.slice(at + sep.length)];
}
export function safePath(path: string, scope = ''): string {
  path = decode(path);
  if (!path || /[\\\0?#:]/.test(path) || path.startsWith('/') || path.split('/').some(x => x === '..')) throw new HttpError(400, 'Invalid resource path');
  path = path.split('/').filter(x => x && x !== '.').join('/');
  scope = scope.replace(/^\.\//, '').replace(/\/$/, '');
  if (scope && path !== scope && !path.startsWith(scope + '/')) throw new HttpError(404, 'Not found');
  return path;
}
export async function readBounded(response: Response | Request, limit = 2 * 1024 * 1024): Promise<string> {
  if (Number(response.headers.get('content-length')) > limit) throw new HttpError(413, 'Resource too large');
  const reader = response.body?.getReader(); if (!reader) return '';
  const decoder = new TextDecoder(); let size = 0, text = '';
  try {
    while (true) { const { done, value } = await reader.read(); if (done) break; size += value.byteLength;
      if (size > limit) throw new HttpError(413, 'Resource too large'); text += decoder.decode(value, { stream: true }); }
    return text + decoder.decode();
  } finally { await reader.cancel().catch(() => undefined); reader.releaseLock(); }
}
export async function digest(s: string): Promise<string> {
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))].map(b => b.toString(16).padStart(2, '0')).join('');
}
export async function tokenEquals(a: string, b: string): Promise<boolean> {
  if (!a || !b) return false;
  const [x, y] = await Promise.all([digest(a), digest(b)]);
  let diff = 0; for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}
export function setPath(root: Dict, path: string, value: unknown): void {
  const parts = path.split('.'); let dest = root;
  for (const [i, part] of parts.entries()) {
    if (['__proto__', 'prototype', 'constructor'].includes(part)) throw new HttpError(400, 'Invalid variable path');
    if (i === parts.length - 1) dest[part] = value;
    else { dest[part] ??= {}; dest = record(dest[part]); }
  }
}
