/**
 * Redaction of secret values typed by journeys.
 *
 * Journey credentials are resolved from the worker's environment at the
 * moment a `fill` step runs. Everything the worker emits afterwards (evidence
 * for the capture, issues, console errors, URLs) passes through
 * `SecretRedactor.deep()`, which replaces every occurrence of a secret value
 * (raw, URL-encoded, base64) with `[REDACTED]`. This is a safety net on top
 * of the primary rule that secret values are never written anywhere in the
 * first place: step errors carry only the step index, type and selector.
 */

export const SECRET_REDACTED = '[REDACTED]';

/** Evidence fields holding base64 bodies; they are opaque and never contain a typed value in readable form. */
const OPAQUE_KEYS = new Set(['bodyBase64', 'textBase64', 'screenshotBase64']);

export class SecretRedactor {
  private variants: string[] = [];
  /** Number of replacements made (reported as an info issue, never with values). */
  hits = 0;

  add(secret: string): void {
    if (secret.length === 0) return;
    const forms = new Set<string>([secret, encodeURIComponent(secret), Buffer.from(secret, 'utf8').toString('base64')]);
    const known = new Set(this.variants);
    for (const f of forms) if (f.length > 0 && !known.has(f)) this.variants.push(f);
    // Longest first, so that overlapping forms are replaced greedily.
    this.variants.sort((a, b) => b.length - a.length);
  }

  get active(): boolean {
    return this.variants.length > 0;
  }

  text(input: string): string {
    let out = input;
    for (const v of this.variants) {
      if (out.includes(v)) {
        this.hits++;
        out = out.split(v).join(SECRET_REDACTED);
      }
    }
    return out;
  }

  /** Returns a deep copy of `value` with secrets removed from every string (object keys included). */
  deep<T>(value: T): T {
    if (!this.active) return value;
    return this.walk(value, undefined) as T;
  }

  private walk(value: unknown, key: string | undefined): unknown {
    if (typeof value === 'string') return key !== undefined && OPAQUE_KEYS.has(key) ? value : this.text(value);
    if (Array.isArray(value)) return value.map((v) => this.walk(v, key));
    if (value !== null && typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) out[this.text(k)] = this.walk(v, k);
      return out;
    }
    return value;
  }
}
