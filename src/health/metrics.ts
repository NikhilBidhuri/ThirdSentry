import { join } from 'node:path';
import { selectFindingsForAlert } from '../alerts/alert-payload.js';
import { CHANNELS, type ChannelName } from '../alerts/channels.js';
import type { ResolvedConfig } from '../config/loader.js';
import type { AlertsConfig } from '../config/schema.js';
import type { FindingState } from '../monitoring/dedup-state.js';
import { SEVERITIES } from '../config/schema.js';
import type { AnalysisReport } from '../types/report.js';
import { pathExists, readJsonFile } from '../utils/fs.js';
import { toolVersion } from '../utils/version.js';
import { loadHealthState, type HealthState } from './health-state.js';

/**
 * Prometheus text exposition (version 0.0.4) of the latest report, the scan
 * health state and the alert state.
 *
 * Conventions: base units (seconds), `_timestamp_seconds` for Unix times, one
 * gauge per fact. Labels are bounded: configured sites, a fixed set of
 * severities/statuses/parties and enabled alert channels. There are no
 * per-script, per-page or per-finding labels.
 */

export interface MetricsInput {
  readonly version: string;
  /** Configured site names: only these are exported (bounded cardinality, renamed sites vanish). */
  readonly sites: readonly string[];
  readonly health: HealthState;
  readonly report?: AnalysisReport;
  /** Findings not yet delivered through each enabled channel. */
  readonly pendingByChannel: Readonly<Record<string, number>>;
}

export function escapeLabelValue(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
}

function escapeHelp(text: string): string {
  return text.replace(/\\/g, '\\\\').replace(/\n/g, '\\n');
}

type Labels = Readonly<Record<string, string>>;

interface Family {
  readonly name: string;
  readonly help: string;
  readonly samples: Array<{ labels: Labels; value: number }>;
}

function formatValue(v: number): string {
  if (Number.isNaN(v)) return 'NaN';
  if (!Number.isFinite(v)) return v > 0 ? '+Inf' : '-Inf';
  return String(v);
}

function render(families: readonly Family[]): string {
  const lines: string[] = [];
  for (const f of families) {
    if (f.samples.length === 0) continue;
    lines.push(`# HELP ${f.name} ${escapeHelp(f.help)}`, `# TYPE ${f.name} gauge`);
    for (const s of f.samples) {
      const keys = Object.keys(s.labels);
      const labels = keys.length ? `{${keys.map((k) => `${k}="${escapeLabelValue(s.labels[k] ?? '')}"`).join(',')}}` : '';
      lines.push(`${f.name}${labels} ${formatValue(s.value)}`);
    }
  }
  return `${lines.join('\n')}\n`;
}

function epochSeconds(iso: string | undefined): number | undefined {
  if (!iso) return undefined;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? ms / 1000 : undefined;
}

export function renderMetrics(input: MetricsInput): string {
  const fam = (name: string, help: string): Family => ({ name, help, samples: [] });
  const info = fam('thirdsentry_info', 'ThirdSentry build information (value is always 1).');
  const lastScan = fam('thirdsentry_last_scan_timestamp_seconds', 'Unix time of the end of the last scan of the site (complete or not).');
  const lastComplete = fam('thirdsentry_last_complete_scan_timestamp_seconds', 'Unix time of the end of the last complete scan of the site.');
  const duration = fam('thirdsentry_scan_duration_seconds', 'Duration of the last scan of the site in seconds.');
  const pages = fam('thirdsentry_pages', 'Pages in the last scan of the site, by scan status.');
  const scripts = fam('thirdsentry_scripts', 'Script resources found in the last scan of the site, by party.');
  const findings = fam('thirdsentry_findings', 'Findings in the latest report, by severity and whether a suppression applies.');
  const failures = fam('thirdsentry_consecutive_failed_scans', 'Failed (or incomplete, per health.countIncomplete) scans in a row for the site.');
  const blocked = fam('thirdsentry_blocked_connections', 'Connections blocked by the network policy in the last scan of the site.');
  const baseline = fam('thirdsentry_baseline_present', '1 if the latest report found an approved baseline for the site, else 0.');
  const delivery = fam('thirdsentry_alert_delivery_failures', 'Consecutive failed alert deliveries per channel (0 after a success).');
  const pending = fam('thirdsentry_alert_pending_findings', 'Findings in the latest report not yet delivered through the channel.');
  const reportTime = fam('thirdsentry_report_timestamp_seconds', 'Unix time the latest report was generated.');

  info.samples.push({ labels: { version: input.version }, value: 1 });
  const generated = epochSeconds(input.report?.generatedAt);
  if (generated !== undefined) reportTime.samples.push({ labels: {}, value: generated });

  for (const site of input.sites) {
    const labels = { site };
    const h = input.health.sites[site];
    if (h) {
      const t = epochSeconds(h.lastScanAt);
      if (t !== undefined) lastScan.samples.push({ labels, value: t });
      const c = epochSeconds(h.lastCompleteAt);
      if (c !== undefined) lastComplete.samples.push({ labels, value: c });
      duration.samples.push({ labels, value: h.lastDurationSeconds });
      for (const status of ['complete', 'partial', 'failed'] as const) pages.samples.push({ labels: { site, status }, value: h.pages[status] });
      scripts.samples.push({ labels: { site, party: 'first-party' }, value: h.scripts.firstParty }, { labels: { site, party: 'third-party' }, value: h.scripts.thirdParty });
      failures.samples.push({ labels, value: h.consecutiveFailures });
      blocked.samples.push({ labels, value: h.blockedConnections });
    }
    const reportSite = input.report?.sites.find((s) => s.name === site);
    if (reportSite) baseline.samples.push({ labels, value: reportSite.baseline.exists ? 1 : 0 });
    if (input.report) {
      for (const severity of SEVERITIES) {
        for (const suppressed of [false, true]) {
          const n = input.report.findings.filter((f) => f.site === site && f.severity === severity && (f.suppressed !== undefined) === suppressed).length;
          findings.samples.push({ labels: { site, severity, suppressed: String(suppressed) }, value: n });
        }
      }
    }
  }
  for (const [channel, h] of Object.entries(input.health.alerts).sort(([a], [b]) => a.localeCompare(b))) {
    if (!(channel in input.pendingByChannel)) continue; // only enabled channels
    delivery.samples.push({ labels: { channel }, value: h.consecutiveFailures });
  }
  for (const [channel, n] of Object.entries(input.pendingByChannel).sort(([a], [b]) => a.localeCompare(b))) {
    pending.samples.push({ labels: { channel }, value: n });
    if (!(channel in input.health.alerts)) delivery.samples.push({ labels: { channel }, value: 0 });
  }
  return render([info, lastScan, lastComplete, duration, pages, scripts, findings, failures, blocked, baseline, reportTime, delivery, pending]);
}

/** Enabled alert channels (generic over the channel list, which grows with new integrations). */
export function enabledAlertChannels(alerts: AlertsConfig): ChannelName[] {
  const cfg = alerts as unknown as Record<string, { enabled?: boolean } | undefined>;
  return CHANNELS.filter((c) => cfg[c]?.enabled === true);
}

async function readLatestReport(path: string): Promise<AnalysisReport | undefined> {
  if (!(await pathExists(path))) return undefined;
  const data = (await readJsonFile(path, 256 * 1024 * 1024)) as Partial<AnalysisReport>;
  if (data.kind !== 'thirdsentry-report' || data.schemaVersion !== 1 || !Array.isArray(data.findings)) return undefined;
  return data as AnalysisReport;
}

/** Read-only view of the finding state (never repairs or rewrites it; the volume may be read-only). */
async function readFindingStateReadOnly(path: string): Promise<FindingState> {
  try {
    if (await pathExists(path)) {
      const data = (await readJsonFile(path, 64 * 1024 * 1024)) as { findings?: unknown };
      if (data.findings && typeof data.findings === 'object') return { version: 2, findings: data.findings as FindingState['findings'] };
    }
  } catch {
    // unreadable state: report nothing as delivered
  }
  return { version: 2, findings: {} };
}

/** Collect everything the exporters render from the files on disk. Read-only. */
export async function collectMetricsInput(resolved: ResolvedConfig, now: Date = new Date()): Promise<MetricsInput> {
  const health = await loadHealthState(resolved.paths);
  const report = await readLatestReport(join(resolved.paths.reports, 'report.json')).catch(() => undefined);
  const pendingByChannel: Record<string, number> = {};
  const alerts = resolved.config.alerts;
  const channels = enabledAlertChannels(alerts);
  if (channels.length > 0) {
    const state = await readFindingStateReadOnly(join(resolved.paths.state, 'findings.json'));
    const cfg = alerts as unknown as Record<string, { minSeverity?: AlertsConfig['minSeverity'] } | undefined>;
    for (const channel of channels) {
      pendingByChannel[channel] = report
        ? selectFindingsForAlert(report, state, { minSeverity: cfg[channel]?.minSeverity ?? alerts.minSeverity, repeatAfterHours: alerts.repeatAfterHours }, now, channel).length
        : 0;
    }
  }
  return { version: toolVersion(), sites: resolved.config.sites.map((s) => s.name), health, ...(report ? { report } : {}), pendingByChannel };
}
