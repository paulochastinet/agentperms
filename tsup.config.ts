import { readFileSync } from 'node:fs';
import { defineConfig } from 'tsup';

const pkg = JSON.parse(readFileSync('./package.json', 'utf8')) as { version: string };

export default defineConfig({
  entry: { cli: 'src/cli.ts', index: 'src/index.ts' },
  format: ['esm'],
  target: 'node18',
  platform: 'node',
  clean: true,
  splitting: true,
  sourcemap: false,
  dts: { entry: { index: 'src/index.ts' } },
  define: { __VERSION__: JSON.stringify(pkg.version) },
  banner: { js: '#!/usr/bin/env node' },
});
