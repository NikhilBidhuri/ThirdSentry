import type { Frame, Page } from 'playwright';
import { redactUrl } from '../security/redaction.js';
import type { FormEvidence, FormSnapshotEvidence } from '../types/evidence.js';
import { withTimeout } from './network-collector.js';

/**
 * Structural snapshot of the forms of a sensitive page (PCI DSS 11.6.1 / Magecart
 * detection): form action, method and field names/types/autocomplete tokens, plus
 * the origins of child frames that host payment-like inputs.
 *
 * Runs inside the untrusted page, so its result is treated as hostile: it is
 * re-validated and size-capped here and again by the evidence schema. Field
 * VALUES are never read. Forms inside closed shadow roots are not visible.
 */

const MAX_FORMS = 100;
const MAX_FIELDS = 200;
const MAX_FRAMES = 50;
const FRAME_TIMEOUT_MS = 4_000;

/** Function source evaluated in each frame. Returns an array of plain form descriptions. */
export const FORM_SNAPSHOT_SCRIPT = `(maxForms, maxFields) => {
  const clip = (v, n) => String(v == null ? '' : v).slice(0, n);
  const resolve = (v) => { try { return new URL(v, document.baseURI).href; } catch (e) { return clip(v, 2048); } };
  const skip = new Set(['submit', 'button', 'reset', 'image']);
  const fieldOf = (el) => {
    const tag = el.tagName.toLowerCase();
    const type = tag === 'input' ? (el.getAttribute('type') || 'text').toLowerCase() : tag;
    if (skip.has(type)) return null;
    return { name: clip(el.getAttribute('name') || el.id || '', 256), type: clip(type, 32), autocomplete: clip(el.getAttribute('autocomplete') || '', 128) };
  };
  const out = [];
  const origin = location.origin === 'null' ? location.protocol : location.origin;
  for (const form of Array.from(document.querySelectorAll('form')).slice(0, maxForms)) {
    const fields = [];
    for (const el of Array.from(form.elements)) {
      if (fields.length >= maxFields) break;
      if (!/^(input|select|textarea)$/i.test(el.tagName)) continue;
      const f = fieldOf(el);
      if (f) fields.push(f);
    }
    const buttonActions = [];
    for (const b of Array.from(form.querySelectorAll('[formaction]')).slice(0, 20)) buttonActions.push(resolve(b.getAttribute('formaction')));
    const rawAction = form.getAttribute('action');
    out.push({ action: rawAction === null ? resolve('') : resolve(rawAction), buttonActions, method: clip(form.getAttribute('method') || 'get', 16), fields, frameOrigin: origin, formless: false });
  }
  const loose = [];
  for (const el of Array.from(document.querySelectorAll('input,select,textarea'))) {
    if (el.form) continue;
    if (loose.length >= maxFields) break;
    const f = fieldOf(el);
    if (f) loose.push(f);
  }
  if (loose.length > 0) out.push({ action: '', buttonActions: [], method: '', fields: loose, frameOrigin: origin, formless: true });
  return out;
}`;

function str(v: unknown, max: number): string {
  return typeof v === 'string' ? v.slice(0, max) : '';
}

function sanitizeForm(raw: unknown): FormEvidence | undefined {
  if (raw === null || typeof raw !== 'object') return undefined;
  const r = raw as Record<string, unknown>;
  const fields = Array.isArray(r.fields) ? r.fields.slice(0, MAX_FIELDS) : [];
  const clean = fields.flatMap((f): FormEvidence['fields'] => {
    if (f === null || typeof f !== 'object') return [];
    const x = f as Record<string, unknown>;
    const autocomplete = str(x.autocomplete, 128);
    return [{ name: str(x.name, 256), type: str(x.type, 32) || 'text', ...(autocomplete ? { autocomplete } : {}) }];
  });
  const formless = r.formless === true;
  return {
    action: formless ? '' : redactUrl(str(r.action, 16_000)),
    buttonActions: (Array.isArray(r.buttonActions) ? r.buttonActions : []).slice(0, 20).map((a) => redactUrl(str(a, 16_000))),
    method: str(r.method, 16),
    fields: clean,
    frameOrigin: str(r.frameOrigin, 2_048),
    formless,
  };
}

function frameOriginOf(frame: Frame): string {
  try {
    const u = new URL(frame.url());
    return u.origin === 'null' ? u.protocol : u.origin;
  } catch {
    return '';
  }
}

/** Payment-like check used only to decide which child frames to report (trusted code recomputes per field). */
const PAYMENT_HINT = /(card|cvv|cvc|cvn|ccnum|expir|cc-(number|csc|exp))/i;

/**
 * Take the form snapshot of a page and all its frames. Never throws: a failure
 * is reported as `status: 'failed'` so that trusted code can degrade coverage
 * instead of reading "no forms" as "nothing changed".
 */
export async function captureFormSnapshot(page: Page, until: number): Promise<FormSnapshotEvidence> {
  const forms: FormEvidence[] = [];
  const paymentFrames = new Set<string>();
  let truncated = false;
  let failed = 0;
  const mainFrame = page.mainFrame();
  const frames = page.frames();
  if (frames.length > MAX_FRAMES) truncated = true;
  for (const frame of frames.slice(0, MAX_FRAMES)) {
    const left = until - Date.now();
    if (left < 250) {
      failed++;
      continue;
    }
    try {
      const raw = await withTimeout(frame.evaluate<unknown>(`(${FORM_SNAPSHOT_SCRIPT})(${MAX_FORMS}, ${MAX_FIELDS})`), Math.min(FRAME_TIMEOUT_MS, left));
      for (const item of Array.isArray(raw) ? raw : []) {
        if (forms.length >= MAX_FORMS) {
          truncated = true;
          break;
        }
        const form = sanitizeForm(item);
        if (!form) continue;
        forms.push(form);
        if (frame !== mainFrame && form.fields.some((f) => PAYMENT_HINT.test(f.name) || PAYMENT_HINT.test(f.autocomplete ?? ''))) {
          const origin = frameOriginOf(frame);
          if (origin) paymentFrames.add(origin);
        }
      }
    } catch {
      // Cross-origin frames that cannot be evaluated or detached frames: counted, not fatal.
      if (frame === mainFrame) failed += 1000;
      else failed++;
    }
  }
  if (failed >= 1000) return { status: 'failed', forms: [], paymentFrames: [], note: 'The main frame could not be inspected for forms' };
  return {
    status: 'captured',
    forms,
    paymentFrames: [...paymentFrames].sort().slice(0, 50),
    ...(truncated ? { truncated: true } : {}),
    ...(failed > 0 ? { note: `${failed} frame(s) could not be inspected` } : {}),
  };
}
