import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { readFile } from 'node:fs/promises';
import { resolve, relative } from 'node:path';

const assets = resolve('base');
export default defineConfig({
  plugins: [cloudflareTest({
    wrangler: { configPath: './wrangler.jsonc' },
    miniflare: {
      bindings: { ACCESS_TOKEN: 'test-secret', GIST_TOKEN: 'test-gist-secret' },
      serviceBindings: {
        ASSETS: async (request) => {
          const path = decodeURIComponent(new URL(request.url).pathname);
          const file = resolve(assets, '.' + path);
          if (relative(assets, file).startsWith('..')) return new Response('Not found', { status: 404 });
          try { return new Response(await readFile(file, 'utf8')); } catch { return new Response('Not found', { status: 404 }); }
        }
      }
    }
  })],
  test: { include: ['test/**/*.test.ts'], fileParallelism: false, testTimeout: 30000 }
});
