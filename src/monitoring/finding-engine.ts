import { createHash } from 'node:crypto';
import { assess, customSignal, signal, type RiskConfig, DEFAULT_RISK_CONFIG } from '../analysis/risk-scoring.js';
import { shortHash } from '../analysis/hashing.js';
import { EMPTY_DOMAIN_POLICY, evaluateDomain } from '../analysis/domain-analyzer.js';
import { RULES_BY_ID } from '../analysis/indicator-rules.js';
import { SEVERITY_WEIGHT } from '../analysis/rule-types.js';
import type { DomainPolicy, RuleConfig } from '../config/schema.js';
import type { Confidence, Evidence, Finding, Signal } from '../types/findings.js';
import type { SiteResult } from '../types/index.js';
import type { Change } from './comparison-engine.js';

/**
 * Turns raw changes into findings that ordinary developers can act on:
 * a title, a plain-language reason, evidence, explainable risk signals and a
 * recommended action. Wording deliberately avoids claiming that a change is
 * malicious: a changed hash is a reason to look, not proof of compromise.
 */

export interface FindingContext {
  readonly site: SiteResult;
  readonly risk?: RiskConfig;
  readonly rules?: Readonly<Record<string, RuleConfig>>;
  readonly domains?: DomainPolicy;
  readonly now?: Date;
}

/** Weight contributed by a match of a rule, honouring configuration overrides. */
export function ruleWeight(ruleId: string, rules: Readonly<Record<string, RuleConfig>> = {}): number {
  const rule = RULES_BY_ID.get(ruleId);
  const cfg = rules[ruleId];
  if (cfg?.weight !== undefined) return cfg.weight;
  return SEVERITY_WEIGHT[cfg?.severity ?? rule?.severity ?? 'low'];
}

/**
 * Behaviour signals for a changed or new resource. Only behaviour that is
 * *new* compared with the approved version contributes: an analytics script
 * that always read cookies does not become suspicious because of a routine
 * update. If the approved version was never analysed, present behaviour
 * counts at half weight.
 */
function behaviourSignals(c: Change, ctx: FindingContext): { signals: Signal[]; evidence: Evidence[] } {
  const current = c.current?.indicators;
  // No indicators at all means analysis did not run (disabled); only a failed analysis is a signal.
  if (!current) return { signals: [], evidence: [] };
  if (!current.analyzed) {
    // An unanalysable script must not look harmless: say so, and score it higher when
    // the approved version could be analysed (the change made analysis impossible).
    const r = c.current;
    if (!r || !r.hashes.sha256 || r.type === 'wasm' || r.normalization.status === 'not-javascript') return { signals: [], evidence: [] };
    const previouslyAnalysed = c.kind !== 'resource-added' && c.baseline?.indicators !== undefined;
    const why = current.error ?? 'no analysis result';
    return {
      signals: [previouslyAnalysed ? signal('analysis-regression', ctx.risk) : signal('analysis-unavailable', ctx.risk)],
      evidence: [{ label: 'Analysis unavailable', value: why.slice(0, 300) }],
    };
  }
  const previous = c.kind === 'resource-added' ? {} : c.baseline?.indicators;
  const signals: Signal[] = [];
  const evidence: Evidence[] = [];
  for (const [ruleId, count] of Object.entries(current.counts)) {
    const rule = RULES_BY_ID.get(ruleId);
    if (!rule || count <= 0) continue;
    const weight = ruleWeight(ruleId, ctx.rules);
    let sig: Signal | undefined;
    if (previous === undefined) {
      sig = customSignal(`rule:${ruleId}`, `Behaviour present (previous version not analysed): ${rule.name}`, Math.round(weight / 2), ctx.risk);
    } else if (count > (previous[ruleId] ?? 0)) {
      sig = customSignal(
        `new-rule:${ruleId}`,
        previous[ruleId] ? `More occurrences of: ${rule.name} (${previous[ruleId]} → ${count})` : `New behaviour: ${rule.name}`,
        weight,
        ctx.risk,
      );
    }
    if (!sig) continue;
    signals.push(sig);
    for (const m of current.matches.filter((x) => x.ruleId === ruleId).slice(0, 2)) {
      evidence.push({ label: `${ruleId} at line ${m.line}`, value: [m.detail, m.snippet].filter(Boolean).join(' | ').slice(0, 300) });
    }
  }
  return { signals, evidence };
}

export function fingerprint(parts: ReadonlyArray<string | null | undefined>): string {
  return `TS-${createHash('sha256').update(parts.map((p) => p ?? '').join('\u0000')).digest('hex').slice(0, 12)}`;
}

function resourceLabel(c: Change): string {
  const r = c.current;
  if (r?.finalUrl) return r.finalUrl;
  if (r?.originalUrl) return r.originalUrl;
  if (c.baseline?.finalUrl) return c.baseline.finalUrl;
  if (c.baseline?.originalUrl) return c.baseline.originalUrl;
  return c.identity ?? c.domain ?? c.origin ?? 'unknown';
}

function isInline(c: Change): boolean {
  return (c.identity ?? '').startsWith('inline:');
}

function previousHashOf(c: Change): string | null {
  const hashes = c.baseline?.approvedHashes ?? [];
  return hashes[hashes.length - 1]?.sha256 ?? null;
}

/** Rules for which whitespace/comments are observable at run time. */
const REFLECTIVE_RULES = ['TS-SOURCE-REFLECTION', 'TS-EVAL', 'TS-NEW-FUNCTION', 'TS-STRING-TIMER'];

const INVESTIGATE_SCRIPT =
  'Compare the new version with the previous one (thirdsentry diff), check the vendor\'s changelog or status page, and confirm the change with the vendor if it is unexpected. If it is legitimate, approve it with "thirdsentry baseline --approve <finding-id>".';

interface Template {
  title: string;
  reason: string;
  action: string;
  signals: Signal[];
  confidence: Confidence;
}

function template(c: Change, ctx: FindingContext, sensitive: boolean): Template {
  const risk = ctx.risk ?? DEFAULT_RISK_CONFIG;
  const s = (id: Parameters<typeof signal>[0]): Signal => signal(id, risk);
  const label = resourceLabel(c);
  const r = c.current;
  const third = (r?.party ?? c.baseline?.party ?? c.details.party) === 'third-party';
  const where = sensitive ? ' on a sensitive page' : '';
  const signals: Signal[] = [];
  if (sensitive) signals.push(s('sensitive-page'));

  switch (c.kind) {
    case 'resource-modified': {
      signals.unshift(isInline(c) ? s('inline-changed') : third ? s('hash-changed-third-party') : s('hash-changed-first-party'));
      if (r?.dynamic) signals.push(s('runtime-injection'));
      const truncated = r?.content.status === 'truncated';
      return {
        title: isInline(c) ? `Inline script changed${where}` : `${third ? 'Third-party' : 'First-party'} script changed${where}`,
        reason: `${isInline(c) ? 'An approved inline script' : `The approved script ${label}`} now has different content (and not only different formatting). Vendors update scripts routinely, so this is not by itself evidence of compromise, but the new code has not been reviewed.`,
        action: INVESTIGATE_SCRIPT,
        signals,
        confidence: truncated ? 'medium' : 'high',
      };
    }
    case 'resource-formatting-changed': {
      const counts = r?.indicators?.counts ?? {};
      const reflective = REFLECTIVE_RULES.some((id) => (counts[id] ?? 0) > 0);
      return {
        title: 'Script reformatted (code unchanged)',
        reason: `The bytes of ${label} changed, but after parsing and normalising whitespace and comments the code is identical to an approved version.${reflective ? ' The script reads its own source text or runs strings as code, so even whitespace and comment changes can alter its behaviour: review it.' : ''}`,
        action: 'No action needed. Approve the new bytes to stop seeing this: thirdsentry baseline --approve <finding-id>.',
        signals: reflective
          ? [s('formatting-only'), s('formatting-with-reflection')]
          : [s('formatting-only')],
        confidence: reflective ? 'medium' : 'high',
      };
    }
    case 'resource-added': {
      const unexpected = c.details.unexpectedType !== undefined;
      signals.unshift(isInline(c) ? s('new-inline-script') : third ? s('new-third-party-script') : s('new-first-party-script'));
      if (r?.dynamic) signals.push(s('runtime-injection'));
      if (unexpected) signals.push(s('unexpected-resource-type'));
      return {
        title: `New ${isInline(c) ? 'inline script' : `${third ? 'third-party' : 'first-party'} ${r?.type ?? 'script'}`}${where}`,
        reason: `${isInline(c) ? 'An inline script' : label} is not in the approved baseline${r?.dynamic ? ' and was injected at runtime by another script' : ''}.${unexpected ? ` Resources of type "${c.details.unexpectedType}" are rarely needed by ordinary pages.` : ''}`,
        action: 'Confirm that someone in your organisation added this script (for example via a tag manager). If not, find out which script injected it before approving it.',
        signals,
        confidence: r?.hashes.sha256 ? 'high' : 'medium',
      };
    }
    case 'resource-removed':
      return {
        title: 'Approved script no longer loads',
        reason: `${label} was in the baseline but was not observed on ${c.pages.join(', ')} even though ${c.pages.length === 1 ? 'that page was' : 'those pages were'} scanned completely.`,
        action: 'If the removal is intended, approve it with thirdsentry baseline --approve <finding-id>. Otherwise check whether the page or a tag manager changed.',
        signals: [s('resource-removed')],
        confidence: 'medium',
      };
    case 'resource-moved': {
      const cross = c.details.previousDomain !== c.details.currentDomain;
      signals.unshift(cross ? s('moved-cross-domain') : s('moved-same-domain'));
      return {
        title: cross ? `Approved script now served from ${c.details.currentDomain}` : 'Approved script moved to a new URL',
        reason: `The same code that was approved as ${c.details.previousIdentity?.replace(/^url:/, '') ?? 'another resource'} is now loaded from ${label}.${cross ? ' A change of hosting domain changes who controls the code.' : ''}`,
        action: cross ? 'Verify that the new domain belongs to the same vendor and is expected.' : 'Usually harmless (renamed or versioned file). Approve the new location.',
        signals,
        confidence: 'high',
      };
    }
    case 'resource-type-changed':
      signals.unshift(s('type-changed'));
      return {
        title: 'Resource loaded as a different type',
        reason: `${label} was approved as "${c.details.previousType}" and is now loaded as "${c.details.currentType}".`,
        action: 'Check why the page now loads this resource differently.',
        signals,
        confidence: 'high',
      };
    case 'redirect-changed': {
      signals.unshift(s('redirect-changed'));
      if (c.details.crossHost === 'true') signals.push(s('redirect-cross-host'));
      return {
        title: c.details.crossHost === 'true' ? 'Script now redirects to a different host' : 'Script redirect destination changed',
        reason: `${c.identity?.replace(/^url:/, '') ?? label} used to redirect to ${c.details.previousFinalUrl} and now redirects to ${c.details.currentFinalUrl}.`,
        action: 'Verify that the new destination is controlled by the expected vendor. Version-pinned URLs avoid unexpected redirects.',
        signals,
        confidence: 'high',
      };
    }
    case 'content-unavailable':
      signals.unshift(s('content-unavailable'));
      return {
        title: 'Script content could not be verified',
        reason: `${label} was observed but its content could not be captured (${c.details.contentStatus}), so ThirdSentry cannot confirm it still matches the approved version.`,
        action: 'Check the scan issues and blocked connections. If the script is now larger than limits.maxResourceBytes, raise the limit.',
        signals,
        confidence: 'low',
      };
    case 'sri-mismatch':
      signals.unshift(s('sri-mismatch'));
      return {
        title: 'Subresource Integrity check fails',
        reason: `The page includes ${label} with integrity="${c.details.integrity}", but the content served does not match. Browsers refuse to run it, so either the page breaks or the content was changed by someone other than the page owner.`,
        action: 'Investigate immediately: confirm with the vendor whether the file was changed, and update the integrity value only after reviewing the new content.',
        signals,
        confidence: 'high',
      };
    case 'new-script-domain': {
      const thirdDomain = c.details.party !== 'first-party';
      signals.unshift(s('new-script-domain'));
      const verdict = evaluateDomain(c.domain ?? '', c.domain, ctx.domains ?? EMPTY_DOMAIN_POLICY);
      if (verdict.ipLiteral) signals.push(s('ip-address-destination'));
      if (verdict.suspicious) signals.push(s('suspicious-domain'));
      return {
        title: `Scripts now loaded from new domain ${c.domain ?? ''}`,
        reason: `This site has never loaded scripts from ${c.domain ?? 'this domain'} before (${c.details.resources ?? ''}).${thirdDomain ? ' Every new script domain is a new party that can run code on your pages.' : ''}`,
        action: 'Confirm that this vendor was added on purpose. If yes, approve the domain; if not, find the script or tag that loads it.',
        signals,
        confidence: 'high',
      };
    }
    case 'new-outbound-domain': {
      const thirdDomain = c.details.party !== 'first-party';
      signals.unshift(thirdDomain ? s('new-outbound-domain-third-party') : s('new-outbound-domain-first-party'));
      const methods = (c.details.methods ?? '').split(',');
      const types = (c.details.resourceTypes ?? '').split(',');
      if (methods.some((m) => m !== 'GET' && m !== 'HEAD' && m !== 'OPTIONS' && m !== '') || types.includes('ping') || types.includes('beacon')) {
        signals.push(s('data-sending-request'));
      }
      if (c.details.blocked === 'true') signals.push(s('blocked-destination'));
      const verdict = evaluateDomain(c.host ?? c.domain ?? '', c.domain, ctx.domains ?? EMPTY_DOMAIN_POLICY);
      if (verdict.ipLiteral) signals.push(s('ip-address-destination'));
      if (verdict.suspicious) signals.push(s('suspicious-domain'));
      return {
        title: `New outbound destination ${c.domain ?? ''}${where}`,
        reason: `The page sent ${c.details.requestCount ?? 'some'} request(s) (${c.details.methods ?? ''}) to ${c.details.hosts ?? c.domain ?? ''}, a domain not contacted in the approved baseline.${c.details.blocked === 'true' ? ' Some of these connections were blocked by the network policy because they pointed at internal addresses.' : ''}`,
        action: 'Check which script sends these requests (browser devtools Network panel, Initiator column) and whether the destination is an expected vendor. Unexpected destinations on checkout or login pages deserve immediate attention.',
        signals,
        confidence: 'high',
      };
    }
    case 'new-outbound-host':
      return {
        title: `New hostname ${c.host ?? ''} under approved domain`,
        reason: `${c.host ?? 'A host'} is contacted for the first time, but its domain ${c.domain ?? ''} is already approved.`,
        action: 'Usually harmless (new vendor endpoint). Approve it to stop seeing this.',
        signals: [s('new-outbound-host'), ...signals],
        confidence: 'high',
      };
    case 'iframe-origin-added':
      signals.unshift(s('iframe-origin-added'));
      return {
        title: `New iframe origin ${c.origin ?? ''}${where}`,
        reason: `The page now embeds content from ${c.origin ?? 'a new origin'}, which is not in the baseline. Iframes can run their own scripts and, on payment pages, can be used to overlay fake forms.`,
        action: 'Confirm that the embedded content is expected.',
        signals,
        confidence: 'high',
      };
    case 'denylisted-domain':
      return {
        title: `Denylisted domain in use: ${c.host ?? c.domain ?? ''}`,
        reason: `${c.host ?? c.domain ?? 'A domain'} matches domains.deny in your configuration and ${c.details.uses ?? 'is used by the page'}.`,
        action: 'Remove the script or request that uses this domain, or update the denylist if the entry is outdated.',
        signals: [s('denylisted-domain'), ...signals],
        confidence: 'high',
      };
    case 'iframe-origin-removed':
      return {
        title: `Iframe origin ${c.origin ?? ''} no longer embedded`,
        reason: `${c.origin ?? 'An approved origin'} was embedded in the baseline but not in this scan.`,
        action: 'Informational. Approve the removal if intended.',
        signals: [s('iframe-origin-removed')],
        confidence: 'medium',
      };
    case 'page-failed':
    case 'coverage-degraded': {
      const failed = c.kind === 'page-failed';
      signals.unshift(s(c.kind));
      const page = c.pages[0] ?? 'a page';
      return {
        title: failed ? `Page could not be scanned${where}: ${page}` : `Scan coverage reduced${where}: ${page}`,
        reason: `${failed ? `${page} failed to scan` : `${page} was only partly scanned`} (${c.details.reason ?? 'unknown'}). ${c.details.issues ?? ''} Changes to scripts on this page cannot be detected until it is scanned completely${sensitive ? ', and it is marked as sensitive' : ''}.`.replace(/\s+/g, ' '),
        action: 'Check whether the page is reachable and whether limits.maxScanDurationMs, limits.maxPagesPerScan or the script/request limits need raising. Treat repeated failures on sensitive pages as an incident: an attacker can serve scanners an error page.',
        signals,
        confidence: 'high',
      };
    }
    default:
      return { title: c.kind, reason: c.kind, action: 'Review the change.', signals, confidence: 'medium' };
  }
}

function evidenceFor(c: Change): Evidence[] {
  const ev: Evidence[] = [];
  const r = c.current;
  const b = c.baseline;
  if (c.identity) ev.push({ label: 'Resource identity', value: c.identity });
  if (r?.originalUrl) ev.push({ label: 'Requested URL', value: r.originalUrl });
  if (r?.finalUrl && r.finalUrl !== r.originalUrl) ev.push({ label: 'Final URL', value: r.finalUrl });
  if (b?.approvedHashes.length) ev.push({ label: 'Approved SHA-256', value: b.approvedHashes.map((h) => h.sha256 ?? 'unavailable').join(', ') });
  if (r) ev.push({ label: 'Current SHA-256', value: r.hashes.sha256 ?? `unavailable (${r.content.status})` });
  if (r?.hashes.normalizedSha256) ev.push({ label: 'Current normalised SHA-256', value: r.hashes.normalizedSha256 });
  if (r?.size !== undefined && b?.approvedHashes.at(-1)?.size !== undefined) {
    ev.push({ label: 'Size', value: `${b.approvedHashes.at(-1)?.size ?? 0} → ${r.size} bytes` });
  }
  if (r?.dynamic) ev.push({ label: 'Injected at runtime', value: 'yes' });
  if (r?.domPath) ev.push({ label: 'DOM position', value: r.domPath });
  for (const [k, v] of Object.entries(c.details)) if (v) ev.push({ label: k, value: v.slice(0, 1000) });
  if (c.pages.length > 0) ev.push({ label: 'Pages', value: c.pages.join(', ') });
  return ev;
}

export function buildFindings(changes: readonly Change[], ctx: FindingContext): Finding[] {
  const detectedAt = (ctx.now ?? new Date()).toISOString();
  const sensitivePages = new Set(ctx.site.pages.filter((p) => p.sensitive).map((p) => p.key));
  const risk = ctx.risk ?? DEFAULT_RISK_CONFIG;
  const newDestinations = changes.filter((c) => c.kind === 'new-outbound-domain' && c.details.party !== 'first-party');
  const pagesWithNewDestination = new Set(newDestinations.flatMap((c) => c.pages));
  const newDestinationDomains = new Set(newDestinations.map((c) => c.domain).filter((d): d is string => d !== undefined));
  const newDestinationHosts = new Set(newDestinations.flatMap((c) => (c.details.hosts ?? '').split(' ').filter(Boolean)));

  return changes.map((c) => {
    const sensitive = c.pages.some((p) => sensitivePages.has(p));
    const t = template(c, ctx, sensitive);
    const extraEvidence: Evidence[] = [];
    if (c.kind === 'resource-modified' || c.kind === 'resource-added' || c.kind === 'resource-moved') {
      const behaviour = behaviourSignals(c, ctx);
      t.signals.push(...behaviour.signals);
      extraEvidence.push(...behaviour.evidence);
      const referenced = (c.current?.indicators?.hosts ?? []).filter((h) => newDestinationHosts.has(h) || [...newDestinationDomains].some((d) => h === d || h.endsWith(`.${d}`)));
      if (referenced.length > 0) {
        t.signals.push(signal('script-references-new-destination', risk));
        extraEvidence.push({ label: 'References new destination', value: referenced.slice(0, 5).join(', ') });
      } else if (c.pages.some((p) => pagesWithNewDestination.has(p))) {
        t.signals.push(signal('correlated-new-destination', risk));
      }
    }
    const a = assess(t.signals, t.confidence, risk);
    const r = c.current;
    const currentHash = r?.hashes.sha256 ?? null;
    const coverage = c.kind === 'page-failed' || c.kind === 'coverage-degraded';
    const subject = c.identity ?? c.domain ?? c.origin ?? c.host ?? (coverage ? c.pages[0] : undefined) ?? '';
    // The host distinguishes findings that share a domain (a.evil.test vs b.evil.test). A
    // new-outbound-domain finding is per domain (its host is just the first one seen), so it is excluded.
    const hostPart = c.kind === 'new-outbound-domain' ? undefined : c.host;
    // Extra parts are appended only for coverage kinds so the IDs of every other kind keep their old format.
    const id = fingerprint([ctx.site.name, c.kind, subject, hostPart, currentHash, c.details.currentFinalUrl, ...(coverage ? [c.details.reason] : [])]);
    const resourceUrl = r?.finalUrl ?? r?.originalUrl ?? c.baseline?.finalUrl ?? c.baseline?.originalUrl;
    const domain = c.domain ?? r?.registrableDomain ?? c.baseline?.registrableDomain;
    const finding: Finding = {
      id,
      kind: c.kind,
      title: t.title,
      site: ctx.site.name,
      pages: c.pages,
      detectedAt,
      severity: a.severity,
      confidence: a.confidence,
      category: a.category,
      score: a.score,
      signals: t.signals,
      reason: t.reason,
      evidence: [...evidenceFor(c), ...extraEvidence],
      recommendedAction: t.action,
      ...(c.pages[0] ? { page: c.pages[0] } : {}),
      ...(c.identity ? { resourceIdentity: c.identity } : {}),
      ...(resourceUrl ? { resourceUrl } : {}),
      ...(r?.type ?? c.baseline?.type ? { resourceType: (r?.type ?? c.baseline?.type) as Finding['resourceType'] & string } : {}),
      ...(r?.party ?? c.baseline?.party ? { party: (r?.party ?? c.baseline?.party) as Finding['party'] & string } : {}),
      ...(domain ? { domain } : {}),
      ...(c.baseline || c.kind === 'resource-modified' ? { previousHash: previousHashOf(c) } : {}),
      ...(r ? { currentHash } : {}),
    };
    return finding;
  });
}

/** One-line human summary used in terminal output and alerts. */
export function findingHeadline(f: Finding): string {
  const hashes = f.previousHash !== undefined || f.currentHash !== undefined ? ` [${shortHash(f.previousHash)} → ${shortHash(f.currentHash)}]` : '';
  return `${f.title}${f.resourceUrl ? `: ${f.resourceUrl}` : ''}${hashes}`;
}
