import { z } from 'zod';
import { PageSecuritySchema } from '../pci/page-security.js';
import { RESOURCE_TYPES } from '../types/index.js';

/**
 * Approved baseline for one site. Stored as stable, sorted JSON in
 * `.thirdsentry/baselines/<site>/baseline.json` so that changes are easy to
 * review in pull requests.
 *
 * Baseline files are validated on every load: they live in Git and may be
 * edited by hand or by other people.
 */

/**
 * Version 2 adds the optional `pageSecurity` map (approved security headers and form
 * fingerprints per page). Version 1 files are upgraded in memory without changes: a
 * missing `pageSecurity` entry means "nothing approved yet".
 */
export const BASELINE_SCHEMA_VERSION = 2;

const sha256 = z.string().regex(/^[0-9a-f]{64}$/, 'must be a lowercase hex SHA-256');

export const ApprovedHashSchema = z
  .object({
    sha256: sha256.nullable(),
    normalizedSha256: sha256.nullable(),
    normalizerVersion: z.string().max(64).nullable(),
    size: z.number().int().min(0).optional(),
    approvedAt: z.string().max(64),
  })
  .strict();

export const BaselineResourceSchema = z
  .object({
    identity: z.string().min(1).max(20_000),
    type: z.enum(RESOURCE_TYPES as [string, ...string[]]),
    party: z.enum(['first-party', 'third-party']),
    pages: z.array(z.string().max(16_384)).max(10_000),
    originalUrl: z.string().max(16_384).optional(),
    finalUrl: z.string().max(16_384).optional(),
    hostname: z.string().max(512).optional(),
    registrableDomain: z.string().max(512).optional(),
    frameContext: z.enum(['main-frame', 'iframe', 'worker', 'unknown']),
    dynamic: z.boolean(),
    /** One or more approved versions. More than one when a vendor legitimately serves variants. */
    approvedHashes: z.array(ApprovedHashSchema).min(1).max(100),
    /** Behaviour indicators (rule id → count) of the approved version (Phase 3). */
    indicators: z.record(z.string().max(128), z.number().int().min(0)).optional(),
  })
  .strict();

export const ApprovalSchema = z
  .object({
    at: z.string().max(64),
    scanId: z.string().max(128),
    scope: z.enum(['initial', 'full', 'selected']),
    reason: z.string().max(2_000).optional(),
    approvedBy: z.string().max(256).optional(),
    items: z.array(z.string().max(20_000)).max(10_000).optional(),
  })
  .strict();

export const BaselineSchema = z
  .object({
    schemaVersion: z.literal(BASELINE_SCHEMA_VERSION),
    kind: z.literal('thirdsentry-baseline'),
    site: z.string().min(1).max(64),
    siteUrl: z.string().max(16_384),
    createdAt: z.string().max(64),
    updatedAt: z.string().max(64),
    approvals: z.array(ApprovalSchema).max(200),
    resources: z.array(BaselineResourceSchema).max(100_000),
    domains: z
      .object({
        /** Registrable domains that serve approved scripts. */
        scripts: z.array(z.string().max(512)),
        /** Registrable domains contacted by approved pages. */
        outbound: z.array(z.string().max(512)),
        /** Hostnames contacted by approved pages. */
        outboundHosts: z.array(z.string().max(512)),
        /** Origins of approved iframes. */
        iframes: z.array(z.string().max(2_048)),
      })
      .strict(),
    /** Pages covered by this baseline (page keys). */
    pages: z.array(z.string().max(16_384)),
    /** Approved security headers and form fingerprint per page key (PCI DSS 11.6.1). Absent in version 1 baselines. */
    pageSecurity: z.record(z.string().max(16_384), PageSecuritySchema).optional(),
  })
  .strict();

export type ApprovedHash = z.infer<typeof ApprovedHashSchema>;
export type BaselineResource = z.infer<typeof BaselineResourceSchema>;
export type Approval = z.infer<typeof ApprovalSchema>;
export type Baseline = z.infer<typeof BaselineSchema>;
