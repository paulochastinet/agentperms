import { run } from './run.js';

run(
  process.argv.slice(2),
  { out: (s) => void process.stdout.write(s), err: (s) => void process.stderr.write(s) },
  { stdout: process.stdout, stderr: process.stderr },
).then(
  (code) => {
    process.exitCode = code;
  },
  (e: unknown) => {
    process.stderr.write(`agentperms: unexpected error: ${(e as Error)?.stack ?? String(e)}\n`);
    process.exitCode = 3;
  },
);
