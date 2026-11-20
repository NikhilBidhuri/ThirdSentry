import { z } from 'zod';
import type { PageResult } from '../types/index.js';
import { FormFingerprintSchema } from './form-fingerprint.js';

/**
 * Approved per-page security state stored in the baseline (`pageSecurity`,
 * keyed by page key): normalised security headers and the form fingerprint.
 * Either part is absent when it was never approved (older baselines, pages
 * without a form snapshot): that means "nothing approved yet", not "empty".
 */
export const PageSecuritySchema = z
  .object({
    headers: z.record(z.string().max(64), z.string().max(65_536)).optional(),
    forms: FormFingerprintSchema.optional(),
    approvedAt: z.string().max(64),
  })
  .strict();

export type PageSecurity = z.infer<typeof PageSecuritySchema>;

export type PageSecurityPart = 'headers' | 'forms';

/** The approvable security state observed on a page in a scan (parts that were not captured are omitted). */
export function observedPageSecurity(page: PageResult, at: string): PageSecurity | undefined {
  if (page.status === 'failed') return undefined;
  if (!page.securityHeaders && !page.formFingerprint) return undefined;
  return {
    ...(page.securityHeaders ? { headers: page.securityHeaders } : {}),
    ...(page.formFingerprint ? { forms: page.formFingerprint } : {}),
    approvedAt: at,
  };
}
