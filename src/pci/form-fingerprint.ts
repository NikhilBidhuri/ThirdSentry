import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { FormSnapshotEvidence } from '../types/evidence.js';

/**
 * Form fingerprints (PCI DSS 11.6.1, Magecart detection).
 *
 * The fingerprint is a canonical, order-independent description of the forms
 * of a page: action origin and path (never the query string), method and the
 * fields (name, type, autocomplete, payment-like). Formatting, attribute order
 * and DOM order do not change it. It contains no field values.
 */

export const FormFieldFpSchema = z
  .object({
    name: z.string().max(256),
    type: z.string().max(32),
    autocomplete: z.string().max(128).optional(),
    payment: z.boolean(),
  })
  .strict();

export const FormFpSchema = z
  .object({
    /** Stable identity within a page: method + action origin/path (or `formless`). */
    key: z.string().max(4_096),
    /** Action origin + path, without query or fragment ('' for formless fields). */
    action: z.string().max(4_096),
    /** Extra targets from formaction attributes (origin + path). */
    buttonActions: z.array(z.string().max(4_096)).max(20),
    method: z.string().max(16),
    formless: z.boolean(),
    fields: z.array(FormFieldFpSchema).max(200),
  })
  .strict();

export const FormFingerprintSchema = z
  .object({
    forms: z.array(FormFpSchema).max(100),
    /** Origins of child frames hosting payment-like inputs. */
    paymentFrames: z.array(z.string().max(2_048)).max(50),
    /** SHA-256 of the canonical content: equal hashes mean "no change". */
    hash: z.string().regex(/^[0-9a-f]{64}$/),
  })
  .strict();

export type FormFieldFp = z.infer<typeof FormFieldFpSchema>;
export type FormFp = z.infer<typeof FormFpSchema>;
export type FormFingerprint = z.infer<typeof FormFingerprintSchema>;

const PAYMENT_AUTOCOMPLETE = /(^|\s)cc-(number|csc|exp|exp-month|exp-year|name|given-name|family-name|additional-name|type)(\s|$)/i;
/** Names such as card, cardNumber, cc_num, cvv, cvc, cvn, pan, expiry, exp-date. */
const PAYMENT_NAME = /(card|cvv|cvc|cvn|ccnum|ccexp|cc[-_ ]?(number|num|exp|csc|no)|expiry|expiration|exp[-_ ]?(date|month|year)|(^|[^a-z])pan([^a-z]|$))/i;

/** Whether a field looks like it collects payment card data. Recomputed here: evidence is untrusted. */
export function isPaymentLike(field: { readonly name: string; readonly type?: string; readonly autocomplete?: string | undefined }): boolean {
  if (field.autocomplete && PAYMENT_AUTOCOMPLETE.test(field.autocomplete)) return true;
  return PAYMENT_NAME.test(field.name);
}

/** Origin + path of a URL (no query, fragment or credentials). Non-URL values are returned truncated. */
export function originAndPath(raw: string): string {
  if (!raw) return '';
  try {
    const u = new URL(raw);
    if (u.origin === 'null') return `${u.protocol}${u.pathname}`.slice(0, 200);
    return `${u.origin}${u.pathname}`;
  } catch {
    return raw.slice(0, 200);
  }
}

export function originOf(raw: string): string {
  try {
    const u = new URL(raw);
    return u.origin === 'null' ? u.protocol : u.origin;
  } catch {
    return '';
  }
}

function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

function fieldKey(f: FormFieldFp): string {
  return `${f.name}\u0000${f.type}\u0000${f.autocomplete ?? ''}`;
}

/** Build the canonical fingerprint from worker evidence. Returns undefined when the snapshot failed. */
export function fingerprintForms(snapshot: FormSnapshotEvidence | undefined): FormFingerprint | undefined {
  if (!snapshot || snapshot.status !== 'captured') return undefined;
  const groups = new Map<string, { form: Omit<FormFp, 'fields'>; fields: Map<string, FormFieldFp> }>();
  for (const f of snapshot.forms) {
    const action = f.formless ? '' : originAndPath(f.action);
    const method = (f.method || 'get').toLowerCase();
    const key = f.formless ? `formless ${f.frameOrigin}` : `${method} ${action}`;
    let group = groups.get(key);
    if (!group) {
      group = { form: { key, action, buttonActions: [], method: f.formless ? '' : method, formless: f.formless }, fields: new Map() };
      groups.set(key, group);
    }
    group.form = { ...group.form, buttonActions: sortedUnique([...group.form.buttonActions, ...f.buttonActions.map(originAndPath)]) };
    for (const field of f.fields) {
      const fp: FormFieldFp = {
        name: field.name.trim().toLowerCase(),
        type: field.type.trim().toLowerCase() || 'text',
        ...(field.autocomplete?.trim() ? { autocomplete: field.autocomplete.trim().toLowerCase().replace(/\s+/g, ' ') } : {}),
        payment: isPaymentLike(field),
      };
      group.fields.set(fieldKey(fp), fp);
    }
  }
  const forms = [...groups.values()]
    .map((g) => ({ ...g.form, fields: [...g.fields.values()].sort((a, b) => fieldKey(a).localeCompare(fieldKey(b))) }))
    .sort((a, b) => a.key.localeCompare(b.key));
  const paymentFrames = sortedUnique(snapshot.paymentFrames);
  const hash = createHash('sha256').update(JSON.stringify({ forms, paymentFrames })).digest('hex');
  return { forms, paymentFrames, hash };
}

export interface FormChangeDetail {
  readonly type:
    | 'payment-form-added'
    | 'form-added'
    | 'form-removed'
    | 'payment-form-removed'
    | 'action-origin-changed'
    | 'action-path-changed'
    | 'method-changed'
    | 'payment-field-added'
    | 'payment-field-removed'
    | 'payment-field-renamed'
    | 'field-added'
    | 'field-removed'
    | 'field-renamed'
    | 'payment-frame-added'
    | 'payment-frame-removed';
  /** Human-readable description for evidence. */
  readonly description: string;
  /** For action changes and added forms: the new action origin and whether it is an external one. */
  readonly externalOrigin?: boolean;
}

function names(fields: readonly FormFieldFp[]): Set<string> {
  return new Set(fields.map((f) => f.name));
}

function similarity(a: FormFp, b: FormFp): number {
  const na = names(a.fields);
  const nb = names(b.fields);
  if (na.size === 0 && nb.size === 0) return a.formless === b.formless ? 0.5 : 0;
  let shared = 0;
  for (const n of na) if (nb.has(n)) shared++;
  return shared / (na.size + nb.size - shared);
}

function describeForm(f: FormFp): string {
  return f.formless ? 'fields outside any form' : `${f.method.toUpperCase()} ${f.action || '(same page)'}`;
}

function hasPayment(f: FormFp): boolean {
  return f.fields.some((x) => x.payment);
}

/** Whether `action` leaves the origins that already belong to the page (its own origin or an approved form target). */
function isExternal(action: string, pageOrigin: string, knownOrigins: ReadonlySet<string>): boolean {
  if (!action) return false;
  const o = originOf(action);
  return o !== '' && o !== pageOrigin && !knownOrigins.has(o);
}

/**
 * Compare the approved form fingerprint of a page with the current one.
 * Reordering, query strings and formatting never produce a detail.
 */
export function diffFormFingerprints(approved: FormFingerprint, current: FormFingerprint, pageOrigin: string): FormChangeDetail[] {
  if (approved.hash === current.hash) return [];
  const out: FormChangeDetail[] = [];
  const known = new Set(approved.forms.map((f) => originOf(f.action)).filter(Boolean));
  const remainingApproved = [...approved.forms];
  const remainingCurrent: FormFp[] = [];
  const pairs: Array<[FormFp, FormFp]> = [];

  for (const c of current.forms) {
    const i = remainingApproved.findIndex((a) => a.key === c.key);
    if (i >= 0) pairs.push([remainingApproved.splice(i, 1)[0] as FormFp, c]);
    else remainingCurrent.push(c);
  }
  // Remaining forms are paired by field overlap (a re-targeted form keeps its fields).
  const candidates: Array<{ a: FormFp; c: FormFp; s: number }> = [];
  for (const c of remainingCurrent) for (const a of remainingApproved) candidates.push({ a, c, s: similarity(a, c) });
  candidates.sort((x, y) => y.s - x.s);
  const usedA = new Set<FormFp>();
  const usedC = new Set<FormFp>();
  for (const { a, c, s } of candidates) {
    if (s < 0.5 || usedA.has(a) || usedC.has(c)) continue;
    usedA.add(a);
    usedC.add(c);
    pairs.push([a, c]);
  }

  for (const [a, c] of pairs) {
    const where = describeForm(c);
    if (a.action !== c.action) {
      const sameOrigin = originOf(a.action) === originOf(c.action);
      out.push({
        type: sameOrigin ? 'action-path-changed' : 'action-origin-changed',
        description: `Form action changed from ${a.action || '(same page)'} to ${c.action || '(same page)'}`,
        ...(sameOrigin ? {} : { externalOrigin: isExternal(c.action, pageOrigin, known) }),
      });
    }
    for (const extra of c.buttonActions) {
      if (!a.buttonActions.includes(extra) && !(extra === a.action) && isExternal(extra, pageOrigin, known)) {
        out.push({ type: 'action-origin-changed', description: `A submit button of ${where} now posts to ${extra} (formaction)`, externalOrigin: true });
      }
    }
    if (!a.formless && !c.formless && a.method !== c.method) {
      out.push({ type: 'method-changed', description: `Form method of ${where} changed from ${a.method.toUpperCase()} to ${c.method.toUpperCase()}` });
    }
    const aFields = new Map(a.fields.map((f) => [f.name, f]));
    const cFields = new Map(c.fields.map((f) => [f.name, f]));
    const added = c.fields.filter((f) => !aFields.has(f.name));
    const removed = a.fields.filter((f) => !cFields.has(f.name));
    const renamedFrom = new Set<string>();
    const renamedTo = new Set<string>();
    // A removed and an added field of the same type and kind count as a rename.
    for (const add of added) {
      const match = removed.find((r) => !renamedFrom.has(r.name) && r.type === add.type && r.payment === add.payment);
      if (match) {
        renamedFrom.add(match.name);
        renamedTo.add(add.name);
        out.push({ type: add.payment ? 'payment-field-renamed' : 'field-renamed', description: `Field "${match.name}" renamed to "${add.name}" in ${where}` });
      }
    }
    for (const add of added) {
      if (renamedTo.has(add.name)) continue;
      out.push({
        type: add.payment ? 'payment-field-added' : 'field-added',
        description: `${add.payment ? 'New payment-like input' : 'New input'} "${add.name}" (${add.type}${add.autocomplete ? `, autocomplete=${add.autocomplete}` : ''}) in ${where}`,
      });
    }
    for (const rem of removed) {
      if (renamedFrom.has(rem.name)) continue;
      out.push({ type: rem.payment ? 'payment-field-removed' : 'field-removed', description: `${rem.payment ? 'Payment-like input' : 'Input'} "${rem.name}" removed from ${where}` });
    }
    // Same name, but type or autocomplete changed (e.g. password-type field turned text, or autocomplete token swapped).
    for (const f of c.fields) {
      const old = aFields.get(f.name);
      if (old && (old.type !== f.type || old.autocomplete !== f.autocomplete) && (old.payment || f.payment)) {
        out.push({ type: 'payment-field-renamed', description: `Payment-like input "${f.name}" in ${where} changed attributes (type ${old.type} to ${f.type}${old.autocomplete !== f.autocomplete ? `, autocomplete ${old.autocomplete ?? 'none'} to ${f.autocomplete ?? 'none'}` : ''})` });
      }
    }
  }

  for (const c of remainingCurrent) {
    if (usedC.has(c)) continue;
    const external = isExternal(c.action, pageOrigin, known);
    out.push({
      type: hasPayment(c) ? 'payment-form-added' : 'form-added',
      description: `New ${hasPayment(c) ? 'payment form' : 'form'} (${describeForm(c)}; fields: ${c.fields.map((f) => f.name).slice(0, 12).join(', ') || 'none'})`,
      externalOrigin: external,
    });
  }
  for (const a of remainingApproved) {
    if (usedA.has(a)) continue;
    out.push({ type: hasPayment(a) ? 'payment-form-removed' : 'form-removed', description: `Approved ${hasPayment(a) ? 'payment form' : 'form'} no longer present (${describeForm(a)})` });
  }

  const approvedFrames = new Set(approved.paymentFrames);
  const currentFrames = new Set(current.paymentFrames);
  for (const o of current.paymentFrames) if (!approvedFrames.has(o)) out.push({ type: 'payment-frame-added', description: `Payment fields are now hosted in an iframe from ${o}`, externalOrigin: o !== pageOrigin });
  for (const o of approved.paymentFrames) if (!currentFrames.has(o)) out.push({ type: 'payment-frame-removed', description: `Payment iframe ${o} no longer hosts payment fields` });
  return out;
}
