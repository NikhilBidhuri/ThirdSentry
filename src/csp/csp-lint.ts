import type { NetworkPolicy } from '../security/network-policy.js';
import { redactUrl } from '../security/redaction.js';
import { safeFetch } from '../security/safe-http.js';
import { analyzePolicies, scriptProfile, type CspFinding } from './csp-analyzer.js';
import { parsePolicies, type Policy } from './csp-parser.js';
import { RECOMMENDATIONS } from './csp-recommendations.js';

/**
 * CSP linting of a URL (live fetch) or of headers captured by a scan.
 * The result never claims that a policy "guarantees" protection.
 */

export const CSP_DISCLAIMER =
  'CSP linting checks the policy text for known weaknesses. A clean result does not guarantee protection: a policy can still allow compromised third-party code from trusted hosts, and CSP does not stop malicious code from a source you allow.';

export interface CspLintTarget {
  readonly url: string;
  readonly finalUrl?: string;
  readonly status?: number;
  readonly source: 'fetch' | 'scan';
  readonly policies: ReadonlyArray<{ readonly index: number; readonly disposition: 'enforce' | 'report'; readonly raw: string }>;
  readonly findings: readonly CspFinding[];
  readonly scriptsRestricted: boolean;
  readonly error?: string;
}

export interface CspLintResult {
  readonly kind: 'thirdsentry-csp-lint';
  readonly generatedAt: string;
  readonly targets: readonly CspLintTarget[];
  readonly counts: { readonly error: number; readonly warning: number; readonly info: number };
  readonly disclaimer: string;
}

function headerValues(raw: ReadonlyArray<[string, string]>, name: string): string[] {
  return raw.filter(([k]) => k === name).map(([, v]) => v);
}

function summarisePolicies(policies: readonly Policy[]): CspLintTarget['policies'] {
  return policies.map((p) => ({ index: p.index, disposition: p.disposition, raw: p.raw.length > 4000 ? `${p.raw.slice(0, 4000)}…` : p.raw }));
}

/** Lint policies given as header values. */
export function lintHeaders(url: string, enforce: readonly string[], reportOnly: readonly string[], source: CspLintTarget['source'], extra: Partial<CspLintTarget> = {}): CspLintTarget {
  const policies = parsePolicies(enforce, reportOnly);
  const analysis = analyzePolicies(policies);
  return { url, source, policies: summarisePolicies(policies), findings: analysis.findings, scriptsRestricted: analysis.scriptsRestricted, ...extra };
}

/** Fetch a URL twice through the SSRF-safe client and lint its CSP headers, including a static-nonce check. */
export async function lintUrl(url: string, policy: NetworkPolicy, options: { timeoutMs?: number } = {}): Promise<CspLintTarget> {
  let first;
  try {
    first = await safeFetch(url, policy, { maxBytes: 512 * 1024, ...(options.timeoutMs ? { timeoutMs: options.timeoutMs } : {}) });
  } catch (error) {
    return { url: redactUrl(url), source: 'fetch', policies: [], findings: [], scriptsRestricted: false, error: error instanceof Error ? error.message : String(error) };
  }
  const enforce = headerValues(first.rawHeaders, 'content-security-policy');
  const reportOnly = headerValues(first.rawHeaders, 'content-security-policy-report-only');
  const target = lintHeaders(redactUrl(url), enforce, reportOnly, 'fetch', { finalUrl: redactUrl(first.url), status: first.status });

  // Static nonce detection: a second response must carry different nonces.
  const nonces = parsePolicies(enforce, reportOnly).flatMap((p) => scriptProfile(p).nonces);
  if (nonces.length > 0) {
    try {
      const second = await safeFetch(url, policy, { maxBytes: 512 * 1024, ...(options.timeoutMs ? { timeoutMs: options.timeoutMs } : {}) });
      const again = parsePolicies(headerValues(second.rawHeaders, 'content-security-policy'), headerValues(second.rawHeaders, 'content-security-policy-report-only')).flatMap((p) => scriptProfile(p).nonces);
      const reused = nonces.filter((n) => again.includes(n));
      if (reused.length > 0) {
        const r = RECOMMENDATIONS['static-nonce'];
        const finding: CspFinding = { id: 'static-nonce', level: r.level, category: 'policy-error', title: r.title, explanation: r.explanation, recommendation: r.recommendation, detail: `The same nonce was returned in two consecutive responses.` };
        return { ...target, findings: [finding, ...target.findings] };
      }
    } catch {
      // A failed second request does not invalidate the first analysis.
    }
  }
  return target;
}

export function buildLintResult(targets: readonly CspLintTarget[], now = new Date()): CspLintResult {
  const counts = { error: 0, warning: 0, info: 0 };
  for (const t of targets) for (const f of t.findings) counts[f.level]++;
  return { kind: 'thirdsentry-csp-lint', generatedAt: now.toISOString(), targets, counts, disclaimer: CSP_DISCLAIMER };
}
