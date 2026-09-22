import { Loader } from './config';
import { array, bool, decode, Dict, HttpError, record, regex, safePath, setPath, str } from './util';

type Expr = { kind: 'value'; value: unknown } | { kind: 'var'; name: string } | { kind: 'call'; name: string; args: Expr[] } |
  { kind: 'get'; object: Expr; key: Expr } | { kind: 'unary'; op: string; value: Expr } | { kind: 'binary'; op: string; left: Expr; right: Expr };
type Token = { text: string; value?: unknown; literal?: boolean };
function expression(source: string): Expr {
  const tokens: Token[] = []; let rest = source.trim();
  while (rest) {
    const m = /^(?:\s+|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(\d+(?:\.\d+)?)|([A-Za-z_]\w*)|(==|!=|>=|<=|[()[\].,+*/%<>!|:-]))/.exec(rest);
    if (!m) throw new HttpError(400, 'Unsupported template expression');
    if (m[1]) { let v: string; try { v = m[1][0] === '"' ? JSON.parse(m[1]) as string : m[1].slice(1, -1).replace(/\\'/g, "'").replace(/\\n/g, '\n').replace(/\\\\/g, '\\'); } catch { throw new HttpError(400, 'Invalid template string'); }
      tokens.push({ text: m[1], literal: true, value: v }); }
    else if (m[2]) tokens.push({ text: m[2], literal: true, value: Number(m[2]) });
    else if (m[3] || m[4]) tokens.push({ text: m[3] ?? m[4] });
    rest = rest.slice(m[0].length);
  }
  let pos = 0;
  const peek = () => tokens[pos]?.text;
  const take = () => tokens[pos++];
  const expect = (s: string) => { if (take()?.text !== s) throw new HttpError(400, 'Malformed template expression'); };
  const priority: Record<string, number> = { or: 1, and: 2, '==': 3, '!=': 3, '>': 3, '<': 3, '>=': 3, '<=': 3, in: 3, '+': 4, '-': 4, '*': 5, '/': 5, '%': 5 };
  const args = (): Expr[] => { expect('('); const a: Expr[] = []; if (peek() !== ')') do { a.push(parse(0)); if (peek() !== ',') break; take(); } while (true); expect(')'); return a; };
  const parse = (min: number): Expr => {
    const t = take(); if (!t) throw new HttpError(400, 'Empty template expression');
    let e: Expr;
    if (t.literal) e = { kind: 'value', value: t.value };
    else if (['true', 'false', 'True', 'False', 'null', 'none', 'None'].includes(t.text)) e = { kind: 'value', value: /^true$/i.test(t.text) ? true : /^false$/i.test(t.text) ? false : null };
    else if (['not', '!', '-'].includes(t.text)) e = { kind: 'unary', op: t.text, value: parse(6) };
    else if (t.text === '(') { e = parse(0); expect(')'); }
    else if (peek() === '(') e = { kind: 'call', name: t.text, args: args() };
    else e = { kind: 'var', name: t.text };
    while (pos < tokens.length) {
      if (peek() === '.') { take(); const k = take(); if (!k) throw new HttpError(400, 'Invalid template property'); e = { kind: 'get', object: e, key: { kind: 'value', value: k.text } }; continue; }
      if (peek() === '[') { take(); const key = parse(0); expect(']'); e = { kind: 'get', object: e, key }; continue; }
      if (peek() === '|') { take(); const name = take()?.text; if (!name) throw new HttpError(400, 'Invalid template filter'); e = { kind: 'call', name, args: [e, ...(peek() === '(' ? args() : [])] }; continue; }
      const op = peek(), rank = priority[op]; if (!rank || rank < min) break;
      take(); e = { kind: 'binary', op, left: e, right: parse(rank + 1) };
    }
    return e;
  };
  const e = parse(0); if (pos !== tokens.length) throw new HttpError(400, 'Unsupported template expression'); return e;
}
type Part = { kind: 'text'; value: string } | { kind: 'expr'; expr: Expr } | { kind: 'set'; name: string; expr: Expr } |
  { kind: 'if'; expr: Expr; yes: Part[]; no: Part[] } | { kind: 'for'; names: string[]; expr: Expr; body: Part[]; empty: Part[] } | { kind: 'include'; expr: Expr };
function parseTemplate(source: string): Part[] {
  source = source.replace(/^\s*#~#\s*(.*)$/gm, '{% $1 %}').replace(/\s+({[{%])- /g, '$1 ').replace(/-([}%]})\s+/g, '$1');
  const chunks = source.split(/({{[\s\S]*?}}|{%[\s\S]*?%}|{#[\s\S]*?#})/g); let pos = 0;
  function parse(stops: string[] = [], depth = 0): { parts: Part[]; stop: string } {
    if (depth > 32) throw new HttpError(400, 'Template nesting limit exceeded');
    const parts: Part[] = [];
    while (pos < chunks.length) {
      const chunk = chunks[pos++]; if (!chunk || chunk.startsWith('{#')) continue;
      if (chunk.startsWith('{{')) { parts.push({ kind: 'expr', expr: expression(chunk.slice(2, -2).trim().replace(/^-|-$/g, '')) }); continue; }
      if (!chunk.startsWith('{%')) { parts.push({ kind: 'text', value: chunk }); continue; }
      const tag = chunk.slice(2, -2).trim().replace(/^-|-$/g, '').trim(), name = tag.split(/\s/)[0];
      if (stops.includes(name)) return { parts, stop: tag };
      if (name === 'if') {
        const branches: Array<{ expr: Expr; parts: Part[] }> = []; let exprText = tag.slice(3), end: { parts: Part[]; stop: string };
        do { end = parse(['elif', 'else', 'endif'], depth + 1); branches.push({ expr: expression(exprText), parts: end.parts }); exprText = end.stop.slice(5); } while (end.stop.startsWith('elif '));
        let tail: Part[] = [];
        if (end.stop === 'else') { end = parse(['endif'], depth + 1); tail = end.parts; }
        if (end.stop !== 'endif') throw new HttpError(400, 'Unclosed template if');
        for (const branch of branches.reverse()) tail = [{ kind: 'if', expr: branch.expr, yes: branch.parts, no: tail }];
        parts.push(...tail);
      } else if (name === 'for') {
        const m = /^for\s+([\w, ]+)\s+in\s+(.+)$/.exec(tag); if (!m) throw new HttpError(400, 'Invalid template for');
        let end = parse(['else', 'endfor'], depth + 1); const body = end.parts; let empty: Part[] = [];
        if (end.stop === 'else') { end = parse(['endfor'], depth + 1); empty = end.parts; }
        if (end.stop !== 'endfor') throw new HttpError(400, 'Unclosed template for');
        parts.push({ kind: 'for', names: m[1].split(',').map(s => s.trim()), expr: expression(m[2]), body, empty });
      } else if (name === 'set') {
        const m = /^set\s+([\w.]+)\s*=\s*(.*)$/.exec(tag); if (!m) throw new HttpError(400, 'Invalid template set'); parts.push({ kind: 'set', name: m[1], expr: expression(m[2]) });
      } else if (name === 'include') parts.push({ kind: 'include', expr: expression(tag.slice(8)) });
      else throw new HttpError(400, `Unsupported template tag: ${name}`);
    }
    return { parts, stop: '' };
  }
  return parse().parts;
}
export async function renderTemplate(text: string, data: Dict, load: Loader, scope = 'base', prefix = '', stack: string[] = []): Promise<string> {
  let operations = 0;
  const get = (obj: unknown, key: unknown): unknown => {
    const k = str(key); if (['__proto__', 'prototype', 'constructor'].includes(k)) throw new HttpError(400, 'Invalid template property');
    if (Array.isArray(obj) || typeof obj === 'string') { if (k === 'length') return obj.length; return obj[Number(k)]; }
    return Object.hasOwn(record(obj), k) ? record(obj)[k] : undefined;
  };
  const pathValue = (path: string, ctx: Dict): unknown => path.split('.').reduce<unknown>((v, k) => get(v, k), ctx);
  async function evaluate(e: Expr, ctx: Dict): Promise<unknown> {
    if (++operations > 100000) throw new HttpError(422, 'Template operation limit exceeded');
    if (e.kind === 'value') return e.value;
    if (e.kind === 'var') return get(ctx, e.name);
    if (e.kind === 'get') return get(await evaluate(e.object, ctx), await evaluate(e.key, ctx));
    if (e.kind === 'unary') { const v = await evaluate(e.value, ctx); return e.op === '-' ? -Number(v) : !v; }
    if (e.kind === 'binary') {
      const a = await evaluate(e.left, ctx);
      if (e.op === 'and') return a && await evaluate(e.right, ctx);
      if (e.op === 'or') return a || await evaluate(e.right, ctx);
      const b = await evaluate(e.right, ctx);
      switch (e.op) {
        case '==': return a === b; case '!=': return a !== b; case '>': return Number(a) > Number(b); case '<': return Number(a) < Number(b);
        case '>=': return Number(a) >= Number(b); case '<=': return Number(a) <= Number(b);
        case '+': return typeof a === 'string' || typeof b === 'string' ? str(a) + str(b) : Number(a) + Number(b);
        case '-': return Number(a) - Number(b); case '*': return Number(a) * Number(b); case '/': return Number(a) / Number(b); case '%': return Number(a) % Number(b);
        case 'in': return Array.isArray(b) ? b.includes(a) : typeof b === 'string' ? b.includes(str(a)) : Object.hasOwn(record(b), str(a));
      }
    }
    if (e.kind !== 'call') throw new HttpError(400, 'Invalid template expression');
    const a: unknown[] = []; for (const arg of e.args) a.push(await evaluate(arg, ctx));
    switch (e.name) {
      case 'default': return a[0] === undefined || a[0] === null ? a[1] : a[0];
      case 'bool': return bool(a[0]) ? 1 : 0; case 'int': case 'float': return Number(a[0]); case 'string': return str(a[0]);
      case 'trim': return str(a[0]).trim(); case 'trim_of': { const c = str(a[1])[0]; let s = str(a[0]); while (c && s.startsWith(c)) s = s.slice(1); while (c && s.endsWith(c)) s = s.slice(0, -1); return s; }
      case 'lower': return str(a[0]).toLowerCase(); case 'upper': return str(a[0]).toUpperCase();
      case 'UrlEncode': return encodeURIComponent(str(a[0])); case 'UrlDecode': return decode(str(a[0]));
      case 'find': return regex(str(a[1])).test(str(a[0])); case 'replace': return str(a[0]).replace(regex(str(a[1]), true), str(a[2]));
      case 'startsWith': return str(a[0]).startsWith(str(a[1])); case 'endsWith': return str(a[0]).endsWith(str(a[1]));
      case 'exists': return pathValue(str(a[0]), ctx) !== undefined; case 'existsIn': return get(a[0], a[1]) !== undefined;
      case 'length': return Array.isArray(a[0]) || typeof a[0] === 'string' ? a[0].length : Object.keys(record(a[0])).length;
      case 'join': return array(a[0]).join(str(a[1], ',')); case 'at': return get(a[0], a[1]);
      case 'first': return array(a[0])[0]; case 'last': return array(a[0]).at(-1);
      case 'range': { const start = a.length > 1 ? Number(a[0]) : 0, stop = Number(a.length > 1 ? a[1] : a[0]); if (stop - start > 2000 || !Number.isFinite(stop - start)) throw new HttpError(422, 'Template range limit exceeded'); return Array.from({ length: Math.max(0, stop - start) }, (_, i) => start + i); }
      case 'round': return Math.round(Number(a[0])); case 'isArray': return Array.isArray(a[0]); case 'isString': return typeof a[0] === 'string';
      case 'tojson': return JSON.stringify(a[0]); case 'getLink': return prefix + str(a[0]);
      case 'fetch': return load(str(a[0]));
      case 'set': setPath(ctx, str(a[0]), a[1]); return '';
      case 'split': { const v = str(a[0]).split(str(a[1])); if (a.length === 3) { setPath(ctx, str(a[2]), v); return ''; } return v; }
      case 'append': setPath(ctx, str(a[0]), str(pathValue(str(a[0]), ctx)) + str(a[1])); return '';
      case 'and': return a.every(Boolean); case 'or': return a.some(Boolean);
      default: throw new HttpError(400, `Unsupported template function: ${e.name}`);
    }
  }
  async function render(parts: Part[], ctx: Dict): Promise<string> {
    let out = '';
    for (const p of parts) {
      if (p.kind === 'text') out += p.value;
      else if (p.kind === 'expr') out += str(await evaluate(p.expr, ctx));
      else if (p.kind === 'set') setPath(ctx, p.name, await evaluate(p.expr, ctx));
      else if (p.kind === 'if') out += await render(await evaluate(p.expr, ctx) ? p.yes : p.no, ctx);
      else if (p.kind === 'include') {
        const path = safePath(str(await evaluate(p.expr, ctx)), scope);
        if (stack.includes(path) || stack.length >= 8) throw new HttpError(400, 'Recursive template include');
        out += await renderTemplate(await load(path), ctx, load, scope, prefix, [...stack, path]);
      } else {
        const value = await evaluate(p.expr, ctx), items = Array.isArray(value) ? value.map((v, i) => [i, v]) : Object.entries(record(value));
        if (items.length > 2000) throw new HttpError(422, 'Template loop limit exceeded');
        if (!items.length) out += await render(p.empty, ctx);
        for (const [i, pair] of items.entries()) {
          const child = { ...ctx, loop: { index: i + 1, index0: i, is_first: i === 0, is_last: i === items.length - 1, first: i === 0, last: i === items.length - 1 } };
          if (p.names.length > 1) { setPath(child, p.names[0], pair[0]); setPath(child, p.names[1], pair[1]); }
          else setPath(child, p.names[0], pair[1]);
          out += await render(p.body, child);
        }
      }
      if (out.length > 2 * 1024 * 1024) throw new HttpError(413, 'Rendered template too large');
    }
    return out;
  }
  return render(parseTemplate(text), data);
}
