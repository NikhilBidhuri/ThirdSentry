import { shortHash } from '../analysis/hashing.js';
import type { Finding, Severity } from '../types/findings.js';
import type { ScanResult, SiteResult } from '../types/index.js';
import type { AnalysisReport } from '../types/report.js';

/**
 * Self-contained, human-readable HTML report.
 *
 * The report embeds strings that originate from scanned (untrusted) pages:
 * URLs, hostnames, console text. Everything is HTML-escaped, the document
 * loads no external resources, and a restrictive Content-Security-Policy
 * meta tag forbids scripts entirely, so a hostile string cannot execute when
 * the report is opened.
 */

export function escapeHtml(value: string | number | boolean | null | undefined): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const e = escapeHtml;

const SEVERITY_LABEL: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

const CATEGORY_TEXT: Record<string, string> = {
  'high-priority': 'Investigate now',
  suspicious: 'Suspicious behaviour',
  review: 'Needs review',
  informational: 'Informational',
};

const STYLE = `
:root{--bg:#f7f7f8;--card:#fff;--text:#1d1d22;--muted:#5d6070;--border:#e2e3e8;--crit:#9b1c1c;--high:#c2410c;--med:#a16207;--low:#1d4ed8;--info:#4b5563;--ok:#15803d}
@media (prefers-color-scheme:dark){:root{--bg:#121216;--card:#1b1b21;--text:#e7e7ec;--muted:#a0a3b1;--border:#2c2d36;--crit:#f87171;--high:#fb923c;--med:#facc15;--low:#60a5fa;--info:#9ca3af;--ok:#4ade80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:32px 0 12px}h3{font-size:16px;margin:0}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;margin:12px 0}
.headline{font-size:17px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.stat{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px}.stat b{display:block;font-size:22px}
.badge{display:inline-block;border-radius:999px;padding:1px 10px;font-size:12px;font-weight:600;border:1px solid currentColor}
.sev-critical{color:var(--crit)}.sev-high{color:var(--high)}.sev-medium{color:var(--med)}.sev-low{color:var(--low)}.sev-info{color:var(--info)}
.ok{color:var(--ok)}.warn{color:var(--med)}.bad{color:var(--crit)}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600}code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}
details{margin-top:8px}summary{cursor:pointer;color:var(--muted)}ul{margin:6px 0;padding-left:20px}
.finding header{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.next{border-left:3px solid var(--low);padding-left:10px;margin-top:8px}
.suppressed{opacity:.65}
`;

function badge(severity: Severity): string {
  return `<span class="badge sev-${escapeHtml(severity)}">${SEVERITY_LABEL[severity] ?? escapeHtml(severity)}</span>`;
}

function renderFinding(f: Finding): string {
  const hashes =
    f.previousHash !== undefined || f.currentHash !== undefined
      ? `<p class="mono muted">previous ${e(f.previousHash ?? 'none')}<br>current&nbsp; ${e(f.currentHash ?? 'none')}</p>`
      : '';
  // Tolerate finding kinds this version does not know (missing optional details).
  const signals = (f.signals ?? []).map((s) => `<li><span class="mono">${s.weight >= 0 ? '+' : ''}${s.weight}</span> ${e(s.description)}</li>`).join('');
  const evidence = (f.evidence ?? []).map((x) => `<tr><th>${e(x.label)}</th><td class="mono">${e(x.value)}</td></tr>`).join('');
  return `<article class="card finding${f.suppressed ? ' suppressed' : ''}" id="${e(f.id)}">
<header>${badge(f.severity)}<h3>${e(f.title || f.kind)}</h3><span class="muted">confidence ${e(f.confidence)} · ${e(CATEGORY_TEXT[f.category] ?? f.category)} · <span class="mono">${e(f.id)}</span>${f.status ? ` · ${e(f.status)}` : ''}</span></header>
${f.suppressed ? `<p class="muted">Suppressed: ${e(f.suppressed.reason)}${f.suppressed.expires ? ` (until ${e(f.suppressed.expires)})` : ''}</p>` : ''}
${f.resourceUrl ? `<p class="mono">${e(f.resourceUrl)}</p>` : ''}
<p>${e(f.reason)}</p>${hashes}
<p class="next"><b>What to do:</b> ${e((f.recommendedAction ?? 'Review the finding.').replace('<finding-id>', f.id))}</p>
<details><summary>Why this rating (score ${f.score})</summary><ul>${signals}</ul></details>
<details><summary>Evidence</summary><table>${evidence}</table></details>
</article>`;
}

function renderPolicies(report: AnalysisReport): string {
  const p = report.policies;
  if (!p) return '';
  const rows = [...p.active, ...p.unused, ...p.expired]
    .map((x) => `<tr><td class="mono">${e(x.name)}</td><td>${e(x.mode)}</td><td>${e(x.scope)}</td><td>${e(x.status)}</td><td>${x.matchedResources}</td><td>${x.acceptedUpdates}</td><td>${x.findings}</td><td>${e(x.owner ?? '')}</td><td>${e(x.expires ?? '')}</td><td>${e(x.reason)}</td></tr>`)
    .join('');
  const matches = p.matches.map((m) => `<tr><td class="mono">${e(m.resource)}</td><td>${e(m.policy)} (${e(m.mode)})</td><td class="mono">${e(m.identity)}</td></tr>`).join('');
  return `<h2>Script policies</h2><div class="card"><table><thead><tr><th>Policy</th><th>Mode</th><th>Scope</th><th>Status</th><th>Scripts</th><th>Accepted updates</th><th>Findings</th><th>Owner</th><th>Expires</th><th>Reason</th></tr></thead><tbody>${rows}</tbody></table>${matches ? `<h3>Policy matches</h3><table><thead><tr><th>Script</th><th>Policy</th><th>Tracked as</th></tr></thead><tbody>${matches}</tbody></table>` : ''}</div>`
}

function renderResources(site: SiteResult): string {
  if (site.resources.length === 0) return '<p class="muted">No script resources observed.</p>';
  const rows = site.resources
    .map((r) => {
      const flags = [r.dynamic ? 'runtime-injected' : '', r.content.status !== 'captured' ? r.content.status : '', r.sri?.valid === false ? 'SRI mismatch' : ''].filter(Boolean);
      const indicators = Object.keys(r.indicators?.counts ?? {});
      return `<tr><td>${e(r.type)}</td><td>${r.party === 'third-party' ? '3rd' : '1st'}</td><td class="mono">${e(r.finalUrl ?? r.originalUrl ?? r.identity)}${flags.length ? `<br><span class="muted">${e(flags.join(', '))}</span>` : ''}</td><td class="mono">${e(shortHash(r.hashes.sha256, 16))}</td><td>${e(r.pages.join(', '))}</td><td class="mono">${e(indicators.join(', '))}</td></tr>`;
    })
    .join('');
  return `<table><thead><tr><th>Type</th><th>Party</th><th>Resource</th><th>SHA-256</th><th>Pages</th><th>Behaviour indicators</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderDestinations(site: SiteResult): string {
  if (site.destinations.length === 0) return '<p class="muted">No outbound requests recorded.</p>';
  const rows = site.destinations
    .map(
      (d) =>
        `<tr><td class="mono">${e(d.hostname)}</td><td>${d.party === 'third-party' ? '3rd' : '1st'}</td><td>${e(d.methods.join(', '))}</td><td>${e(d.resourceTypes.join(', '))}</td><td>${d.requestCount}</td><td>${d.blocked ? '<span class="bad">blocked</span>' : ''}</td></tr>`,
    )
    .join('');
  return `<table><thead><tr><th>Host</th><th>Party</th><th>Methods</th><th>Types</th><th>Requests</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
}

export function renderHtmlReport(report: AnalysisReport, scan?: ScanResult): string {
  const s = report.scanSummary;
  const active = report.findings.filter((f) => !f.suppressed);
  const suppressed = report.findings.filter((f) => f.suppressed);
  const statusClass = report.scanStatus === 'complete' ? 'ok' : report.scanStatus === 'partial' ? 'warn' : 'bad';
  const counts = (['critical', 'high', 'medium', 'low', 'info'] as const)
    .map((sev) => `<div class="stat"><span class="sev-${sev}">${SEVERITY_LABEL[sev]}</span><b>${report.findingCounts[sev]}</b></div>`)
    .join('');
  const siteRows = report.sites
    .map(
      (site) =>
        `<tr><td>${e(site.name)}</td><td class="mono">${e(site.url)}</td><td>${e(site.status)}</td><td>${site.baseline.exists ? `approved ${e(site.baseline.approvedAt ?? '')}` : '<span class="warn">no baseline</span>'}</td><td>${site.unchangedResources}</td><td>${site.newResources}</td><td>${site.modifiedResources}</td><td>${site.removedResources}</td><td>${e(site.newDomains.join(', '))}</td></tr>`,
    )
    .join('');
  const failures = (scan?.sites ?? [])
    .flatMap((site) => [
      ...site.issues.map((i) => ({ where: site.name, ...i })),
      ...site.pages.flatMap((p) => p.issues.map((i) => ({ where: `${site.name} ${p.key}`, ...i }))),
    ])
    .filter((i) => i.level !== 'info');
  const pages = (scan?.sites ?? []).flatMap((site) => site.pages.map((p) => ({ site: site.name, ...p })));

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>ThirdSentry report</title><style>${STYLE}</style></head>
<body><main>
<h1>ThirdSentry report</h1>
<p class="muted">Scan <span class="mono">${e(report.scanId)}</span> · ${e(report.scanStartedAt)} → ${e(report.scanFinishedAt)} · scan status <b class="${statusClass}">${e(report.scanStatus)}</b> · ThirdSentry ${e(report.toolVersion)}</p>
<div class="card headline">${e(report.headline)}</div>
<p class="muted">ThirdSentry reports changes and behaviour worth reviewing. A finding is a reason to look, not proof of compromise; "no findings" does not prove that scripts are safe. See the coverage limitations below.</p>

<h2>Summary</h2>
<div class="grid">
<div class="stat">Pages scanned<b>${s.pages}</b><span class="muted">${s.pagesComplete} complete · ${s.pagesPartial} partial · ${s.pagesFailed} failed</span></div>
<div class="stat">Script resources<b>${s.resources}</b><span class="muted">${s.firstPartyResources} first-party · ${s.thirdPartyResources} third-party</span></div>
<div class="stat">Third-party domains<b>${s.thirdPartyDomains}</b></div>
<div class="stat">Blocked connections<b>${s.blockedConnections}</b></div>
</div>
<h2>Findings by severity</h2><div class="grid">${counts}</div>

<h2>Sites</h2>
<div class="card"><table><thead><tr><th>Site</th><th>URL</th><th>Scan</th><th>Baseline</th><th>Unchanged</th><th>New</th><th>Modified</th><th>Removed</th><th>New domains</th></tr></thead><tbody>${siteRows}</tbody></table></div>

${renderPolicies(report)}
<h2>Findings (${active.length})</h2>
${active.length === 0 ? '<p class="muted">No active findings.</p>' : active.map(renderFinding).join('\n')}
${suppressed.length ? `<h2>Suppressed findings (${suppressed.length})</h2>${suppressed.map(renderFinding).join('\n')}` : ''}

${failures.length ? `<h2>Scan problems</h2><div class="card"><table><thead><tr><th>Where</th><th>Level</th><th>Code</th><th>Message</th></tr></thead><tbody>${failures.map((i) => `<tr><td>${e(i.where)}</td><td>${e(i.level)}</td><td class="mono">${e(i.code)}</td><td>${e(i.message)}</td></tr>`).join('')}</tbody></table></div>` : ''}

${pages.length ? `<h2>Pages</h2><div class="card"><table><thead><tr><th>Site</th><th>Page</th><th>Status</th><th>Scripts</th><th>Requests</th><th>Sensitive</th></tr></thead><tbody>${pages.map((p) => `<tr><td>${e(p.site)}</td><td class="mono">${e(p.key)}</td><td>${e(p.status)}</td><td>${p.resourceKeys.length}</td><td>${p.requests.length}</td><td>${p.sensitive ? 'yes' : ''}</td></tr>`).join('')}</tbody></table></div>` : ''}

${(scan?.sites ?? []).map((site) => `<h2>Scripts on ${e(site.name)}</h2><div class="card">${renderResources(site)}</div><h2>Outbound destinations of ${e(site.name)}</h2><div class="card">${renderDestinations(site)}</div>`).join('\n')}

<h2>Coverage limitations</h2>
<div class="card"><ul>${report.coverageLimitations.map((l) => `<li>${e(l)}</li>`).join('')}</ul></div>
<p class="muted">Generated ${e(report.generatedAt)}. Report data: ${e(report.scanPath)}.</p>
</main></body></html>
`;
}
