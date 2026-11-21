import { parse as parseDomain } from 'tldts';
import { z } from 'zod';
import { matchesAnyHost, normalizeHost } from '../utils/patterns.js';

/**
 * Logged-in, multi-step journeys (docs/configuration.md#journeys).
 *
 * A journey is a small declarative script (goto, click, fill, ...) that the
 * browser worker runs in ONE browser context so that cookies persist between
 * steps; each `capture` step records evidence for the current page under the
 * stable page key `journey:<journey>/<capture>`.
 *
 * This module is pure (no Playwright) so that configuration loading, the
 * worker sandbox and the browser worker all share the same rules.
 *
 * SECRETS: the only place a secret may be referenced is the `value` of a
 * `fill` step, and only as `${THIRDSENTRY_SECRET_<NAME>}`. Any other `${...}`
 * is rejected when the configuration is loaded.
 */

export const JOURNEY_SECRET_PREFIX = 'THIRDSENTRY_SECRET_';
const SECRET_NAME = /^THIRDSENTRY_SECRET_[A-Z0-9_]+$/;
export const MAX_JOURNEY_STEPS = 100;
export const MAX_JOURNEYS_PER_SITE = 20;
export const DEFAULT_JOURNEY_TIMEOUT_MS = 120_000;
/** Resolved secrets shorter than this are refused: redacting them from evidence would corrupt unrelated text. */
export const MIN_SECRET_LENGTH = 8;

export function isSecretName(name: string): boolean {
  return SECRET_NAME.test(name);
}

/** Names referenced as `${NAME}` in a value, plus anything that is not an allowed reference. */
export function parseSecretRefs(value: string): { names: string[]; problems: string[] } {
  const names: string[] = [];
  const problems: string[] = [];
  for (const m of value.matchAll(/\$\{([^}]*)\}/g)) {
    const name = m[1] ?? '';
    if (isSecretName(name)) names.push(name);
    else problems.push(name === '' ? '${}' : `\${${name.slice(0, 64)}}`);
  }
  if (value.replace(/\$\{[^}]*\}/g, '').includes('${')) problems.push('unterminated "${"');
  return { names, problems };
}

/** Replace `${THIRDSENTRY_SECRET_X}` references using `env`. Never throws; reports what is missing. */
export function substituteSecrets(
  value: string,
  env: Readonly<Record<string, string | undefined>>,
): { value: string; secrets: string[]; missing: string[]; short: string[] } {
  const secrets: string[] = [];
  const missing: string[] = [];
  const short: string[] = [];
  const out = value.replace(/\$\{([^}]*)\}/g, (whole, name: string) => {
    if (!isSecretName(name)) return whole;
    const v = env[name];
    if (v === undefined || v === '') {
      missing.push(name);
      return '';
    }
    if (v.length < MIN_SECRET_LENGTH) short.push(name);
    secrets.push(v);
    return v;
  });
  return { value: out, secrets, missing, short };
}

const selector = z.string().min(1).max(512);
const stepTimeout = z.number().int().min(500).max(120_000).optional();
const noSecrets = (v: string): boolean => !v.includes('${');
const NO_SECRETS_MESSAGE = 'only the "value" of a "fill" step may reference ${THIRDSENTRY_SECRET_<NAME>}';
const plain = (max: number): z.ZodString => z.string().min(1).max(max).refine(noSecrets, NO_SECRETS_MESSAGE);
const pageName = z.string().regex(/^[a-z0-9][a-z0-9._-]{0,63}$/i, 'must be 1-64 characters: letters, digits, ".", "_" or "-"');
const hostPattern = z
  .string()
  .min(1)
  .regex(/^(\*|(\*\.)?[a-z0-9_.:[\]-]+)$/i, 'must be a hostname, "*.example.com" or "*"');

export const JourneyStepSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('goto'), url: plain(2048), timeoutMs: stepTimeout }).strict(),
  z
    .object({
      type: z.literal('click'),
      selector: selector.refine(noSecrets, NO_SECRETS_MESSAGE),
      /** Required to click a submit button of a payment-like form. Never use with live payment credentials. */
      allowSubmit: z.boolean().default(false),
      timeoutMs: stepTimeout,
    })
    .strict(),
  z
    .object({
      type: z.literal('fill'),
      selector: selector.refine(noSecrets, NO_SECRETS_MESSAGE),
      /** Literal text or text containing ${THIRDSENTRY_SECRET_<NAME>} references. */
      value: z.string().max(4096).superRefine((v, ctx) => {
        for (const problem of parseSecretRefs(v).problems) {
          ctx.addIssue({
            code: 'custom',
            message: `${problem} is not allowed: fill values may only reference \${THIRDSENTRY_SECRET_<NAME>} (uppercase letters, digits, "_")`,
          });
        }
      }),
      timeoutMs: stepTimeout,
    })
    .strict(),
  z.object({ type: z.literal('select'), selector: selector.refine(noSecrets, NO_SECRETS_MESSAGE), value: plain(512), timeoutMs: stepTimeout }).strict(),
  z.object({ type: z.literal('check'), selector: selector.refine(noSecrets, NO_SECRETS_MESSAGE), checked: z.boolean().default(true), timeoutMs: stepTimeout }).strict(),
  z
    .object({
      type: z.literal('press'),
      selector: selector.refine(noSecrets, NO_SECRETS_MESSAGE).optional(),
      key: z.string().regex(/^[A-Za-z0-9]+(\+[A-Za-z0-9]+)*$/, 'must be a key name such as "Enter" or "Control+A"').max(64),
      /** Required to press Enter in a field of a payment-like form. */
      allowSubmit: z.boolean().default(false),
      timeoutMs: stepTimeout,
    })
    .strict(),
  z
    .object({
      type: z.literal('waitFor'),
      selector: selector.refine(noSecrets, NO_SECRETS_MESSAGE).optional(),
      /** URL glob, e.g. "**\/checkout" (a leading "/" is treated as "**" + path). */
      url: plain(2048).optional(),
      loadState: z.enum(['load', 'domcontentloaded', 'networkidle']).optional(),
      timeoutMs: stepTimeout,
    })
    .strict()
    .refine((s) => [s.selector, s.url, s.loadState].filter((v) => v !== undefined).length === 1, 'waitFor needs exactly one of selector, url or loadState'),
  z.object({ type: z.literal('capture'), name: pageName, sensitive: z.boolean().optional() }).strict(),
]);

export const JourneySchema = z
  .object({
    name: pageName,
    /** Findings on this journey's captures are scored as sensitive (payments, accounts). Per-capture `sensitive` overrides. */
    sensitive: z.boolean().default(false),
    /** Playwright storageState file (an authenticated session) to start from instead of, or before, scripted login. */
    storageState: z.string().min(1).max(1024).optional(),
    /** Extra hosts `goto` and navigation may use besides the site's own registrable domain. */
    allowedHosts: z.array(hostPattern).max(50).default([]),
    /** Wall-clock limit for the whole journey (also bounded by the scan deadline). */
    timeoutMs: z.number().int().min(5_000).max(600_000).default(DEFAULT_JOURNEY_TIMEOUT_MS),
    steps: z.array(JourneyStepSchema).min(1).max(MAX_JOURNEY_STEPS),
  })
  .strict()
  .superRefine((j, ctx) => {
    const seen = new Set<string>();
    j.steps.forEach((s, i) => {
      if (s.type !== 'capture') return;
      if (seen.has(s.name)) ctx.addIssue({ code: 'custom', path: ['steps', i, 'name'], message: `duplicate capture name "${s.name}"` });
      seen.add(s.name);
    });
    if (seen.size === 0) ctx.addIssue({ code: 'custom', path: ['steps'], message: 'a journey needs at least one "capture" step; otherwise it records nothing' });
  });

export type JourneyStep = z.infer<typeof JourneyStepSchema>;
export type JourneyConfig = z.infer<typeof JourneySchema>;

/** Page key of a journey capture in baselines, findings and reports. */
export function journeyPageKey(journey: string, capture: string): string {
  return `journey:${journey}/${capture}`;
}

/** Secret variable names referenced by the journeys of these sites (the only extra variables the worker receives). */
export function journeySecretNames(sites: ReadonlyArray<{ readonly journeys?: ReadonlyArray<{ readonly steps: ReadonlyArray<{ readonly type: string; readonly value?: string }> }> }>): string[] {
  const names = new Set<string>();
  for (const site of sites) {
    for (const journey of site.journeys ?? []) {
      for (const step of journey.steps) {
        if (step.type === 'fill' && typeof step.value === 'string') for (const n of parseSecretRefs(step.value).names) names.add(n);
      }
    }
  }
  return [...names].sort();
}

function registrableOrHost(host: string): string {
  const h = normalizeHost(host);
  return parseDomain(h).domain ?? h;
}

/** Is navigating to `host` allowed for a journey of a site on `siteHost`? Same registrable domain, or listed in allowedHosts. */
export function journeyHostAllowed(host: string, siteHost: string, allowedHosts: readonly string[]): boolean {
  if (registrableOrHost(host) === registrableOrHost(siteHost)) return true;
  return matchesAnyHost(host, allowedHosts);
}
