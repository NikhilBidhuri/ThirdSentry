import { customSignal, signal, DEFAULT_RISK_CONFIG, type RiskConfig, type SIGNALS } from '../analysis/risk-scoring.js';
import type { Change } from '../monitoring/comparison-engine.js';
import type { Confidence, Signal } from '../types/findings.js';
import type { FormChangeDetail } from './form-fingerprint.js';
import type { HeaderChange } from './security-headers.js';

/**
 * Titles, explanations, next steps and explainable risk signals for the PCI
 * related change kinds. Called by the finding engine (src/monitoring/finding-engine.ts).
 */

export interface PciTemplate {
  title: string;
  reason: string;
  action: string;
  signals: Signal[];
  confidence: Confidence;
}

const APPROVE = 'If the change is intended and was reviewed, approve it with "thirdsentry baseline --approve <finding-id>".';

type SignalId = keyof typeof SIGNALS;

/** One signal per distinct id (a repeated change adds its count to the description, not to the score). */
function collapse(signals: Signal[]): Signal[] {
  const out = new Map<string, { s: Signal; n: number }>();
  for (const s of signals) {
    const e = out.get(s.id);
    if (e) e.n++;
    else out.set(s.id, { s, n: 1 });
  }
  return [...out.values()].map(({ s, n }) => (n > 1 ? { ...s, description: `${s.description} (${n} times)` } : s));
}

function headerTemplate(c: Change, sensitive: boolean, risk: RiskConfig): PciTemplate {
  const changes: readonly HeaderChange[] = c.pci?.headerChanges ?? [];
  const weakened = changes.filter((h) => h.direction === 'weakened');
  const strengthened = changes.filter((h) => h.direction === 'strengthened');
  const page = c.pages[0] ?? 'a page';
  const signals: Signal[] = [];
  for (const h of weakened) signals.push(customSignal(`header-weakened:${h.header}`, h.summary.slice(0, 300), h.weight, risk));
  if (weakened.length > 0 && sensitive) signals.unshift(signal('sensitive-page', risk));
  if (weakened.length === 0) {
    for (const h of changes) signals.push(customSignal(`header-${h.direction}:${h.header}`, h.summary.slice(0, 300), h.weight, risk));
  }
  const names = [...new Set(changes.map((h) => h.header))].join(', ');
  const removed = weakened.filter((h) => h.kind === 'removed');
  let title: string;
  if (weakened.length === 0) title = `Security headers changed (strengthened) on ${page}`;
  else if (removed.length > 0) title = `Security header removed${sensitive ? ' on a payment page' : ''}: ${removed.map((h) => h.header).join(', ')}`;
  else title = `Security header weakened${sensitive ? ' on a payment page' : ''}: ${weakened.map((h) => h.header).join(', ')}`;
  const reason =
    weakened.length > 0
      ? `The HTTP response headers of ${page} no longer protect it as strongly as the approved baseline (${names}). ${weakened.map((h) => h.summary).join(' ')}${
          strengthened.length ? ` Other headers were strengthened: ${strengthened.map((h) => h.header).join(', ')}.` : ''
        } Weakened headers on payment pages are a PCI DSS 11.6.1 concern: they can enable script injection or framing.`
      : `The approved security headers of ${page} changed in the direction of stronger protection (${names}). ${changes.map((h) => h.summary).join(' ')}`;
  return {
    title,
    reason,
    action:
      weakened.length > 0
        ? `Find out who changed the web server, CDN or WAF configuration and why. Restore the header if the change was not intended. ${APPROVE}`
        : `No action needed. Approve the new headers to stop seeing this: thirdsentry baseline --approve <finding-id>.`,
    signals,
    confidence: 'high',
  };
}

const FORM_SIGNAL: Record<FormChangeDetail['type'], SignalId> = {
  'payment-form-added': 'payment-form-added',
  'form-added': 'form-added',
  'form-removed': 'form-removed',
  'payment-form-removed': 'payment-form-removed',
  'action-origin-changed': 'form-action-origin-changed',
  'action-path-changed': 'form-action-path-changed',
  'method-changed': 'form-method-changed',
  'payment-field-added': 'payment-field-added',
  'payment-field-removed': 'payment-field-removed',
  'payment-field-renamed': 'payment-field-renamed',
  'field-added': 'form-field-changed',
  'field-removed': 'form-field-changed',
  'field-renamed': 'form-field-changed',
  'payment-frame-added': 'payment-frame-added',
  'payment-frame-removed': 'payment-frame-removed',
};

function formTemplate(c: Change, sensitive: boolean, risk: RiskConfig): PciTemplate {
  const changes: readonly FormChangeDetail[] = c.pci?.formChanges ?? [];
  const page = c.pages[0] ?? 'a page';
  const signals: Signal[] = [];
  if (sensitive) signals.push(signal('sensitive-page', risk));
  for (const d of changes) {
    signals.push(signal(FORM_SIGNAL[d.type], risk));
    if (d.externalOrigin) signals.push(signal('form-action-external', risk));
  }
  const has = (t: FormChangeDetail['type']): boolean => changes.some((d) => d.type === t);
  let title: string;
  if (has('action-origin-changed')) title = `Payment form now submits to a different origin: ${page}`;
  else if (has('payment-form-added')) title = `New payment form appeared on ${page}`;
  else if (has('payment-field-added')) title = `New payment input added to a form on ${page}`;
  else if (has('payment-frame-added')) title = `Payment fields are now hosted in a new iframe on ${page}`;
  else if (has('payment-field-removed') || has('payment-field-renamed') || has('payment-form-removed')) title = `Payment form structure changed on ${page}`;
  else title = `Form structure changed on ${page}`;
  const injected = has('payment-form-added') || has('payment-field-added') || has('action-origin-changed');
  return {
    title,
    reason: `The structure of the forms on ${page} differs from the approved baseline: ${changes.map((d) => d.description).slice(0, 8).join('; ')}.${
      injected ? ' Injecting a fake card form or re-targeting a form action are the classic ways skimmers (Magecart) steal card data, but a deliberate checkout change looks the same.' : ''
    }`,
    action: `Compare the page source with your last release and check which script modifies the form (browser devtools, Elements and Network panels). Treat an unexpected form action or card field as an incident. ${APPROVE}`,
    signals: collapse(signals),
    confidence: 'high',
  };
}

function missingTemplate(c: Change, risk: RiskConfig): PciTemplate {
  const pages = (c.details.pages ?? '').split(', ').filter(Boolean);
  return {
    title: 'Security headers and forms are not baselined yet',
    reason: `The approved baseline was created before ThirdSentry recorded security headers and payment-form structure (or the pages are new), so there is nothing to compare for: ${pages.slice(0, 10).join(', ')}${pages.length > 10 ? ', ...' : ''}. This is not a change on the site; header and form changes are not detected for these pages until their current state is approved.`,
    action: 'Review the current scan, then record it with "thirdsentry baseline" (or approve this finding with "thirdsentry baseline --approve <finding-id>").',
    signals: [signal('security-baseline-missing', risk)],
    confidence: 'high',
  };
}

export function pciTemplate(c: Change, sensitive: boolean, risk: RiskConfig = DEFAULT_RISK_CONFIG): PciTemplate | undefined {
  switch (c.kind) {
    case 'security-header-changed':
      return headerTemplate(c, sensitive, risk);
    case 'payment-form-changed':
      return formTemplate(c, sensitive, risk);
    case 'security-baseline-missing':
      return missingTemplate(c, risk);
    default:
      return undefined;
  }
}
