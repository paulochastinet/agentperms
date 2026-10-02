import type { TargetId } from '../types.js';
import { claude } from './claude.js';
import { codex } from './codex.js';
import type { Target } from './common.js';
import { cursor } from './cursor.js';
import { gemini } from './gemini.js';

export const TARGETS: Record<TargetId, Target> = { claude, codex, gemini, cursor };
export * from './common.js';
