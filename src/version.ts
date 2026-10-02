declare const __VERSION__: string | undefined;

/** Injected at build time by tsup (see tsup.config.ts). */
export const VERSION: string = typeof __VERSION__ === 'string' ? __VERSION__ : '0.1.0';
