import { z } from 'zod';
import { parse as parseDomain } from 'tldts';

/**
 * Configuration schema of `scriptPolicies` (see docs/policies.md).
 *
 * A policy is an explicit, reviewable statement about vendor scripts whose
 * URL or content rotates. Every matcher is bound to a host or domain, so a
 * policy can never cover a script served from another registrable domain.
 */

export const POLICY_MODES = ['pin', 'path-versions', 'domain-only'] as const;
export type PolicyMode = (typeof POLICY_MODES)[number];

const NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
const HEX_SHA256 = /^[0-9a-f]{64}$/i;
const SRI_HASH = /^(sha256|sha384)-([A-Za-z0-9+/_-]+)={0,2}$/;

const stringList = z
  .union([z.string().min(1).max(4096), z.array(z.string().min(1).max(4096)).min(1).max(1000)])
  .transform((v) => (Array.isArray(v) ? v : [v]));

export const PolicyMatchSchema = z
  .object({
    /** Exact canonical URL (query parameters listed in the site's ignoreQueryParams are ignored). */
    url: stringList.optional(),
    /** URL prefix: same origin, and the path (plus query) starts with the prefix's path. */
    urlPrefix: stringList.optional(),
    /** Glob over the canonical URL: `https://<host or *.domain>/<path glob>`. The host part cannot contain other wildcards. */
    glob: stringList.optional(),
    /** Exact resource identity as printed in findings (`url:https://...`). Inline, blob and data identities are rejected. */
    identity: stringList.optional(),
    /** Registrable domain (eTLD+1) such as `vendor.com`; covers every host below it. */
    domain: stringList.optional(),
    /** Hostname (`cdn.vendor.com`) or `*.vendor.com`. */
    host: stringList.optional(),
    /** Page keys / globs (`/checkout`, `/shop/*`). A script seen on any page outside the list is not covered. */
    pages: stringList.optional(),
  })
  .strict();

export const PolicyHashSchema = z
  .string()
  .refine((h) => {
    if (HEX_SHA256.test(h)) return true;
    const m = SRI_HASH.exec(h);
    if (!m) return false;
    const b64 = (m[2] as string).replace(/-/g, '+').replace(/_/g, '/');
    return m[1] === 'sha256' ? b64.length === 44 || b64.length === 43 : b64.length === 64 || b64.length === 63;
  }, 'must be a SHA-256 hex digest (64 hex characters) or an SRI hash (sha256-... / sha384-...)');

export const ScriptPolicySchema = z
  .object({
    name: z.string().regex(NAME, 'must be 1-64 characters: letters, digits, ".", "_" or "-"'),
    match: PolicyMatchSchema,
    mode: z.enum(POLICY_MODES),
    /** Why this policy exists. Required: undocumented policies are not allowed. */
    reason: z.string().min(3).max(2_000),
    /** ISO date after which the policy stops applying (date-only values are valid through the end of that day, UTC). */
    expires: z
      .string()
      .refine((v) => !Number.isNaN(Date.parse(v)), 'must be an ISO date such as 2026-12-31')
      .optional(),
    owner: z.string().min(1).max(256).optional(),
    /** `pin` mode: allowed content hashes. */
    hashes: z.array(PolicyHashSchema).min(1).max(200).optional(),
  })
  .strict()
  .superRefine((p, ctx) => {
    const m = p.match;
    const matchers = [m.url, m.urlPrefix, m.glob, m.identity, m.domain, m.host];
    if (matchers.every((x) => x === undefined)) {
      ctx.addIssue({ code: 'custom', path: ['match'], message: 'needs at least one of url, urlPrefix, glob, identity, domain or host' });
    }
    const bad = (key: string, i: number, message: string): void => {
      ctx.addIssue({ code: 'custom', path: ['match', key, i], message });
    };
    const INLINE = 'policies apply to URL-identified scripts only; inline, blob: and data: scripts cannot be matched';
    const httpUrl = (value: string): URL | undefined => {
      if (/^(inline|blob|data):/i.test(value)) return undefined;
      try {
        const u = new URL(value);
        return u.protocol === 'http:' || u.protocol === 'https:' ? u : undefined;
      } catch {
        return undefined;
      }
    };
    (m.url ?? []).forEach((v, i) => {
      if (!httpUrl(v)) bad('url', i, /^(inline|blob|data):/i.test(v) ? INLINE : 'must be an absolute http(s) URL');
    });
    (m.urlPrefix ?? []).forEach((v, i) => {
      if (!httpUrl(v)) bad('urlPrefix', i, /^(inline|blob|data):/i.test(v) ? INLINE : 'must be an absolute http(s) URL');
    });
    (m.identity ?? []).forEach((v, i) => {
      if (/^(inline|blob|data):/i.test(v)) bad('identity', i, INLINE);
      else if (!v.startsWith('url:') || !httpUrl(v.slice(4))) bad('identity', i, 'must look like "url:https://host/path" (copy it from a finding)');
    });
    (m.glob ?? []).forEach((v, i) => {
      if (/^(inline|blob|data):/i.test(v)) return bad('glob', i, INLINE);
      const g = /^(https?):\/\/([^/]+)(\/.*)?$/.exec(v);
      if (!g) return bad('glob', i, 'must look like "https://host/path/*.js" (scheme and host are required)');
      const host = g[2] as string;
      if (host.includes('*') || host.includes('?')) {
        const wildcardOk = host.startsWith('*.') && !host.slice(2).includes('*') && !host.includes('?') && registrableOrDeeper(host.slice(2));
        if (!wildcardOk) bad('glob', i, 'the host part may only be a hostname or "*.<registrable domain>" (wildcards elsewhere in the host would let the policy cover other domains)');
      }
    });
    (m.domain ?? []).forEach((v, i) => {
      if (v.includes('*') || v.includes('/') || v.includes(':')) return bad('domain', i, 'must be a registrable domain such as vendor.com (use host for hostnames and wildcards)');
      const d = parseDomain(v.toLowerCase(), { allowPrivateDomains: true }).domain;
      if (d !== v.toLowerCase()) bad('domain', i, `must be a registrable domain such as vendor.com${d ? ` (did you mean ${d}?)` : ''}`);
    });
    (m.host ?? []).forEach((v, i) => {
      const h = v.toLowerCase();
      if (h === '*' || h.includes('/') || h.includes(':')) return bad('host', i, 'must be a hostname such as cdn.vendor.com or "*.vendor.com"');
      if (h.startsWith('*.')) {
        if (h.slice(2).includes('*') || !registrableOrDeeper(h.slice(2))) bad('host', i, '"*." must be followed by a registrable domain or a host below it (for example *.vendor.com)');
      } else if (h.includes('*') || !/^[a-z0-9_.-]+$/.test(h)) bad('host', i, 'must be a hostname such as cdn.vendor.com or "*.vendor.com"');
    });
    (m.pages ?? []).forEach((v, i) => {
      if (!v.startsWith('/') && !v.startsWith('*') && !/^https?:/i.test(v)) bad('pages', i, 'must be a page key such as "/checkout" (globs with * are allowed)');
    });
    if (p.mode === 'pin') {
      if (!p.hashes) ctx.addIssue({ code: 'custom', path: ['hashes'], message: 'mode "pin" needs "hashes": the allowed SHA-256 hex or SRI (sha384-...) digests' });
    } else if (p.hashes) {
      ctx.addIssue({ code: 'custom', path: ['hashes'], message: `"hashes" is only valid with mode "pin" (mode is "${p.mode}")` });
    }
  });

function registrableOrDeeper(base: string): boolean {
  const b = base.toLowerCase();
  const d = parseDomain(b, { allowPrivateDomains: true }).domain;
  return d !== null && (b === d || b.endsWith(`.${d}`));
}

export type ScriptPolicy = z.infer<typeof ScriptPolicySchema>;
export type PolicyMatch = z.infer<typeof PolicyMatchSchema>;

/** Policy names must be unique per site (they become the resource identity `policy:<name>`). */
export function checkPolicyNames(
  global: readonly ScriptPolicy[],
  sites: ReadonlyArray<{ readonly name: string; readonly scriptPolicies: readonly ScriptPolicy[] }>,
  report: (path: Array<string | number>, message: string) => void,
): void {
  const globalNames = new Set<string>();
  global.forEach((p, i) => {
    const n = p.name.toLowerCase();
    if (globalNames.has(n)) report(['scriptPolicies', i, 'name'], `duplicate script policy name "${p.name}"`);
    globalNames.add(n);
  });
  sites.forEach((site, si) => {
    const seen = new Set<string>();
    site.scriptPolicies.forEach((p, i) => {
      const n = p.name.toLowerCase();
      if (globalNames.has(n)) report(['sites', si, 'scriptPolicies', i, 'name'], `script policy "${p.name}" has the same name as a global policy; names must be unique`);
      else if (seen.has(n)) report(['sites', si, 'scriptPolicies', i, 'name'], `duplicate script policy name "${p.name}"`);
      seen.add(n);
    });
  });
}
