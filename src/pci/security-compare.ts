import { createHash } from 'node:crypto';
import type { Baseline } from '../baseline/baseline-schema.js';
import type { Change } from '../monitoring/comparison-engine.js';
import type { PageResult, SiteResult } from '../types/index.js';
import { diffFormFingerprints, originOf } from './form-fingerprint.js';
import type { PageSecurityPart } from './page-security.js';
import { diffSecurityHeaders } from './security-headers.js';

/**
 * Compare the security headers and form fingerprints of the scanned pages with
 * the approved ones (PCI DSS 11.6.1). Facts only; the finding engine assigns severity.
 *
 * A page whose baseline has no approved headers/forms yet (older baselines, new
 * pages, a page that only recently became sensitive) is NOT a change: it yields
 * one `security-baseline-missing` notice per site.
 */

function digest(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex').slice(0, 16);
}

function pageOrigin(page: PageResult): string {
  return originOf(page.finalUrl ?? page.url);
}

export function compareSecurity(site: SiteResult, baseline: Baseline): Change[] {
  const changes: Change[] = [];
  const pending: Array<{ page: string; part: PageSecurityPart }> = [];

  for (const page of site.pages) {
    if (page.status === 'failed') continue;
    const approved = baseline.pageSecurity?.[page.key];

    if (page.securityHeaders) {
      if (!approved?.headers) {
        pending.push({ page: page.key, part: 'headers' });
      } else {
        const diff = diffSecurityHeaders(approved.headers, page.securityHeaders);
        if (diff.length > 0) {
          const details: Record<string, string> = {};
          diff.forEach((d, i) => {
            details[`Header change ${i + 1}`] = `${d.direction}: ${d.summary}`;
          });
          changes.push({
            kind: 'security-header-changed',
            pages: [page.key],
            details,
            pci: { subject: page.key, idPart: digest(diff.map((d) => [d.header, d.after ?? null])), headerChanges: diff },
          });
        }
      }
    }

    if (page.formSnapshotFailed) {
      if (approved?.forms) {
        changes.push({
          kind: 'coverage-degraded',
          pages: [page.key],
          details: { reason: 'form-snapshot-failed', issues: 'The form snapshot of this sensitive page could not be taken, so changes to payment forms cannot be detected.' },
        });
      }
    } else if (page.formFingerprint) {
      if (!approved?.forms) {
        pending.push({ page: page.key, part: 'forms' });
      } else {
        const diff = diffFormFingerprints(approved.forms, page.formFingerprint, pageOrigin(page));
        if (diff.length > 0) {
          const details: Record<string, string> = {};
          diff.forEach((d, i) => {
            details[`Form change ${i + 1}`] = `${d.type}: ${d.description}`;
          });
          changes.push({
            kind: 'payment-form-changed',
            pages: [page.key],
            details,
            pci: { subject: page.key, idPart: page.formFingerprint.hash.slice(0, 16), formChanges: diff },
          });
        }
      }
    }
  }

  if (pending.length > 0) {
    const pages = [...new Set(pending.map((p) => p.page))].sort();
    changes.push({
      kind: 'security-baseline-missing',
      // No pages on the change itself: this is a notice about the baseline, not about a sensitive page.
      pages: [],
      details: {
        pages: pages.join(', '),
        parts: `${pending.filter((p) => p.part === 'headers').length} page(s) without approved security headers, ${pending.filter((p) => p.part === 'forms').length} sensitive page(s) without an approved form fingerprint`,
      },
      pci: { subject: 'security-baseline', idPart: '', pending },
    });
  }
  return changes;
}
