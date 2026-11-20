import type { FormChangeDetail } from './form-fingerprint.js';
import type { PageSecurityPart } from './page-security.js';
import type { HeaderChange } from './security-headers.js';

/**
 * Structured payload carried by the PCI-related changes
 * (`security-header-changed`, `payment-form-changed`, `security-baseline-missing`).
 * The finding engine turns it into signals; the baseline command into approval items.
 */
export interface PciChangePayload {
  /** Stable subject of the finding ID (page key, or "security-baseline"). */
  readonly subject: string;
  /** Extra finding ID component describing the current state (so a further change gets a new ID). */
  readonly idPart: string;
  readonly headerChanges?: readonly HeaderChange[];
  readonly formChanges?: readonly FormChangeDetail[];
  /** For security-baseline-missing: the page parts that have no approved state yet. */
  readonly pending?: ReadonlyArray<{ readonly page: string; readonly part: PageSecurityPart }>;
}
