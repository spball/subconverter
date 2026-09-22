import { expect, vi } from 'vitest';

// A strict, one-shot HTTP fixture queue. Unexpected network calls fail closed.
type Fixture = { url: string; method: string; status: number; body: string; headers?: HeadersInit };
let fixtures: Fixture[] = [];
export const fetchMock = {
  activate() {
    fixtures = [];
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      const method = init?.method ?? (input instanceof Request ? input.method : 'GET');
      const at = fixtures.findIndex(f => f.url === url && f.method === method);
      if (at < 0) throw new Error(`Unexpected outbound request: ${method} ${new URL(url).origin}`);
      const f = fixtures.splice(at, 1)[0]; return new Response(f.body, { status: f.status, headers: f.headers });
    }));
  },
  disableNetConnect() {},
  get(origin: string) {
    return { intercept({ path, method = 'GET' }: { path: string; method?: string }) {
      return { reply(status: number, body: string, options: { headers?: HeadersInit } = {}) { fixtures.push({ url: origin + path, method, status, body, headers: options.headers }); } };
    } };
  },
  assertNoPendingInterceptors() { expect(fixtures).toHaveLength(0); },
  deactivate() { vi.unstubAllGlobals(); fixtures = []; }
};
