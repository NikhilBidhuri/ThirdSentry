/**
 * Byte budgets for evidence recorded by the browser worker.
 *
 * A hostile page controls how much data it makes the worker record (huge
 * blobs, thousands of object URLs, endless inline scripts). Without a bound
 * the worker eventually fails to serialise the evidence ("Invalid string
 * length") or runs out of heap, and the evidence of *every* site is lost.
 *
 * Every recorded body, inline text, blob and metadata record is charged
 * against a per-page and a per-scan budget. Content (bodies, texts,
 * screenshots) is refused once the content budget is exhausted; metadata
 * records may use an extra headroom so that the network facts (which URLs
 * were loaded) survive a content flood. Every refusal is counted so the page
 * can be marked partial with an explicit issue.
 */

/** Share of the page/scan budget that is reserved for metadata once content is exhausted. */
const METADATA_HEADROOM = 0.25;

export type BudgetKind = 'content' | 'meta';

export class ScanEvidenceBudget {
  used = 0;
  readonly maxBytes: number;

  constructor(maxBytes: number) {
    this.maxBytes = Math.max(0, Math.floor(maxBytes));
  }

  /** Create the budget for one page, charged against this scan budget. */
  page(maxPageBytes: number): PageEvidenceBudget {
    return new PageEvidenceBudget(maxPageBytes, this);
  }

  limitFor(kind: BudgetKind): number {
    return kind === 'content' ? this.maxBytes : Math.floor(this.maxBytes * (1 + METADATA_HEADROOM));
  }
}

export class PageEvidenceBudget {
  used = 0;
  /** Number of items (bodies, texts, records) refused because a budget was exhausted. */
  refused = 0;
  /** True when the per-scan (rather than per-page) budget caused a refusal. */
  scanExhausted = false;
  readonly maxBytes: number;
  private readonly scan: ScanEvidenceBudget;

  constructor(maxBytes: number, scan: ScanEvidenceBudget) {
    this.maxBytes = Math.max(0, Math.floor(maxBytes));
    this.scan = scan;
  }

  private limitFor(kind: BudgetKind): number {
    return kind === 'content' ? this.maxBytes : Math.floor(this.maxBytes * (1 + METADATA_HEADROOM));
  }

  /** True if `bytes` of `kind` would currently fit (does not reserve or count). */
  canFit(bytes: number, kind: BudgetKind = 'content'): boolean {
    const n = Math.max(0, Math.ceil(bytes));
    return this.used + n <= this.limitFor(kind) && this.scan.used + n <= this.scan.limitFor(kind);
  }

  /** Reserve `bytes`; returns false (and counts the refusal) when a budget would be exceeded. */
  tryReserve(bytes: number, kind: BudgetKind = 'content'): boolean {
    const n = Math.max(0, Math.ceil(bytes));
    if (this.used + n > this.limitFor(kind)) {
      this.refused++;
      return false;
    }
    if (this.scan.used + n > this.scan.limitFor(kind)) {
      this.refused++;
      this.scanExhausted = true;
      return false;
    }
    this.used += n;
    this.scan.used += n;
    return true;
  }
}

/** Length of a base64 encoding of `bytes` bytes. */
export function base64Length(bytes: number): number {
  return Math.ceil(bytes / 3) * 4;
}

/** Serialised JSON size of a (small) value; used to charge metadata and page-controlled text. */
export function jsonSize(value: unknown): number {
  try {
    return JSON.stringify(value)?.length ?? 0;
  } catch {
    return 0;
  }
}

/** Effective per-scan budget: never more than 75% of what the analyser accepts. */
export function effectiveScanBudget(limits: { maxEvidenceBytesPerScan?: number; maxEvidenceBytes: number }): number {
  const configured = limits.maxEvidenceBytesPerScan ?? 256 * 1024 * 1024;
  return Math.min(configured, Math.floor(limits.maxEvidenceBytes * 0.75));
}

/** Longest URL the evidence schema accepts (see src/types/evidence.ts). */
export const MAX_EVIDENCE_URL = 16_384;

/**
 * Clamp a URL to the schema limit. A single over-long URL would otherwise make
 * the whole page's evidence fail validation. Callers count truncations and
 * report them as an issue.
 */
export function clampUrl(raw: string, onTruncate?: () => void): string {
  if (raw.length <= MAX_EVIDENCE_URL) return raw;
  onTruncate?.();
  return raw.slice(0, MAX_EVIDENCE_URL);
}
