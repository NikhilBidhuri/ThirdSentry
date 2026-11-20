import type { ResolvedConfig } from '../config/loader.js';
import type { AlertsConfig, Severity } from '../config/schema.js';
import { loadFindingState, openAlerts, recordAlerted, recordResolved, saveFindingState, type FindingState } from '../monitoring/dedup-state.js';
import type { Finding } from '../types/findings.js';
import type { AnalysisReport } from '../types/report.js';
import { ThirdSentryError } from '../utils/errors.js';
import { getLogger } from '../utils/logger.js';
import { buildAlertPayload, selectFindingsForAlert, type AlertPayload } from './alert-payload.js';
import { CHANNELS, type ChannelName } from './channels.js';
import { parseRecipients, sendEmail } from './email.js';
import { isLiteralSecret, redactSecrets, resolveEnv } from './env.js';
import { createGithubIssues } from './github-issues.js';
import { AlertDeliveryError, type FetchLike } from './http.js';
import { sendPagerDuty } from './pagerduty.js';
import { sendSlack } from './slack.js';
import { sendTeams } from './teams.js';
import { sendWebhook } from './webhook.js';

/**
 * Alert publisher. Runs after a report has been written and is the only
 * component that resolves alert credentials. Delivery problems are reported
 * and logged but never affect scan results or reports.
 *
 * Delivery is tracked per channel. A finding counts as delivered to a channel
 * only when it was individually listed in a message that the channel accepted
 * (for GitHub: an issue was created, or an open issue for it already exists).
 * Findings that a channel could not list (maxFindingsPerAlert, Slack's block
 * limits, maxIssuesPerRun, a failed request) stay pending for that channel
 * and are selected again on the next run.
 */

export { CHANNELS, type ChannelName } from './channels.js';

export interface ChannelResult {
  readonly channel: ChannelName;
  readonly ok: boolean;
  /** Findings delivered through this channel in this run. */
  readonly delivered: number;
  /** Findings selected for this channel (in a dry run: would be sent). */
  readonly selected: number;
  /** Selected findings not delivered in this run; they are retried on the next run. */
  readonly pending: number;
  readonly attempts: number;
  readonly detail?: string;
  readonly error?: string;
}

export interface AlertRunResult {
  /** Distinct findings selected for at least one channel. */
  readonly selected: number;
  /** Enabled channels that were considered (empty: no channel is enabled). */
  readonly channels: readonly ChannelName[];
  readonly results: readonly ChannelResult[];
  readonly dryRun: boolean;
  /** True for `alert --test` runs (synthetic message, state untouched). */
  readonly test?: boolean;
  /** Alert built from every selected finding (what a channel without its own threshold receives). */
  readonly payload?: AlertPayload;
}

export interface AlertRunOptions {
  readonly env?: NodeJS.ProcessEnv;
  readonly now?: Date;
  readonly dryRun?: boolean;
  /** Send a clearly-labelled synthetic alert through each enabled channel; does not read or change state. */
  readonly test?: boolean;
  readonly channels?: readonly ChannelName[];
  readonly fetchImpl?: FetchLike;
  /** Base delay between retries (ms); doubled per attempt. */
  readonly retryDelayMs?: number;
  /**
   * Fallback report location shown in alerts (e.g. the local report path).
   * A configured alerts.reportUrl always takes precedence.
   */
  readonly reportLocation?: string;
}

function enabledChannels(alerts: AlertsConfig, only?: readonly ChannelName[]): ChannelName[] {
  return CHANNELS.filter((c) => alerts[c].enabled && (!only || only.includes(c)));
}

/**
 * Only failures explicitly marked as transient are retried. Configuration
 * errors (missing environment variables, invalid URLs), authentication
 * failures and other permanent errors are not: repeating them cannot succeed
 * and, for SMTP authentication, can lock the account.
 */
export function isRetryable(error: unknown): boolean {
  return error instanceof AlertDeliveryError && error.retryable;
}

async function withRetries<T>(fn: () => Promise<T>, retries: number, baseDelayMs: number): Promise<{ value: T; attempts: number }> {
  let attempt = 0;
  for (;;) {
    attempt++;
    try {
      return { value: await fn(), attempts: attempt };
    } catch (error) {
      if (!isRetryable(error) || attempt > retries) throw Object.assign(error instanceof Error ? error : new Error(String(error)), { attempts: attempt });
      await new Promise((r) => setTimeout(r, baseDelayMs * 2 ** (attempt - 1)));
    }
  }
}

/** Warn when credentials are written literally into the configuration. */
export function literalSecretWarnings(alerts: AlertsConfig): string[] {
  const warnings: string[] = [];
  if (alerts.slack.enabled && isLiteralSecret(alerts.slack.webhookUrl)) warnings.push('alerts.slack.webhookUrl');
  if (alerts.webhook.enabled && isLiteralSecret(alerts.webhook.secret)) warnings.push('alerts.webhook.secret');
  if (alerts.github.enabled && isLiteralSecret(alerts.github.token)) warnings.push('alerts.github.token');
  if (alerts.email.enabled && isLiteralSecret(alerts.email.password)) warnings.push('alerts.email.password');
  if (alerts.pagerduty.enabled && isLiteralSecret(alerts.pagerduty.routingKey)) warnings.push('alerts.pagerduty.routingKey');
  if (alerts.teams.enabled && isLiteralSecret(alerts.teams.webhookUrl)) warnings.push('alerts.teams.webhookUrl');
  return warnings;
}

/** alerts.reportUrl (when configured and resolvable) wins over the caller's local path. */
export function resolveReportLocation(alerts: AlertsConfig, env: NodeJS.ProcessEnv, fallback: string): string {
  if (alerts.reportUrl) {
    try {
      return resolveEnv(alerts.reportUrl, env, 'alerts.reportUrl');
    } catch (error) {
      getLogger('alerts').warn({ err: (error as Error).message }, 'alerts.reportUrl could not be resolved; alerts show the local report path instead');
    }
  }
  return fallback;
}

/** Synthetic alert used by `thirdsentry alert --test`. */
export function testPayload(reportLocation: string, now: Date): AlertPayload {
  return {
    schemaVersion: 1,
    kind: 'thirdsentry-alert',
    generatedAt: now.toISOString(),
    scanId: 'test',
    scanStatus: 'complete',
    headline: 'ThirdSentry test alert: if you can read this, delivery through this channel works. This is not a real finding.',
    sites: ['thirdsentry-test'],
    highestSeverity: 'info',
    counts: { info: 1, low: 0, medium: 0, high: 0, critical: 0 },
    reportLocation,
    findings: [
      {
        id: 'TS-000000000000',
        title: 'Test alert (not a real finding)',
        severity: 'info',
        confidence: 'high',
        category: 'informational',
        site: 'thirdsentry-test',
        pages: [],
        reason: 'Sent by "thirdsentry alert --test" to check that this alert channel is configured correctly.',
        why: 'test message',
        evidence: [],
        recommendedAction: 'Nothing to do. If this arrived, alert delivery works.',
      },
    ],
    omitted: 0,
    test: true,
  };
}

interface Delivery {
  /** Finding IDs delivered (see the module comment). */
  readonly ids: readonly string[];
  readonly detail?: string;
  /** Findings whose open event was resolved (PagerDuty autoResolve). */
  readonly resolved?: readonly string[];
  /** A failure after part of the work was done (GitHub, PagerDuty). */
  readonly error?: Error;
}

interface ChannelContext {
  readonly alerts: AlertsConfig;
  readonly env: NodeJS.ProcessEnv;
  readonly now: Date;
  readonly fetchImpl?: FetchLike;
  readonly retryDelayMs: number;
  /** Finding IDs whose PagerDuty event should be resolved in this run (autoResolve). */
  readonly resolveIds?: readonly string[];
}

async function deliver(channel: ChannelName, payload: AlertPayload, ctx: ChannelContext, secrets: string[]): Promise<{ delivery: Delivery; attempts: number }> {
  const { alerts, env, now } = ctx;
  const resolve = (value: string, setting: string): string => {
    const v = resolveEnv(value, env, setting);
    secrets.push(v);
    return v;
  };
  const common = { timeoutMs: alerts.timeoutMs, ...(ctx.fetchImpl ? { fetchImpl: ctx.fetchImpl } : {}) };
  switch (channel) {
    case 'slack': {
      const webhookUrl = resolve(alerts.slack.webhookUrl, 'alerts.slack.webhookUrl');
      const { value, attempts } = await withRetries(() => sendSlack(payload, webhookUrl, common), alerts.retries, ctx.retryDelayMs);
      return { delivery: { ids: value }, attempts };
    }
    case 'webhook': {
      const secret = alerts.webhook.secret ? resolve(alerts.webhook.secret, 'alerts.webhook.secret') : undefined;
      const target = { url: resolve(alerts.webhook.url, 'alerts.webhook.url'), allowInsecureHttp: alerts.webhook.allowInsecureHttp, ...(secret ? { secret } : {}) };
      const { value, attempts } = await withRetries(() => sendWebhook(payload, target, { ...common, now }), alerts.retries, ctx.retryDelayMs);
      return { delivery: { ids: value }, attempts };
    }
    case 'github': {
      if (!alerts.github.createIssues) return { delivery: { ids: [], detail: 'createIssues is false' }, attempts: 0 };
      // Never retried automatically: a timed-out create may have succeeded.
      const outcome = await createGithubIssues(
        payload,
        {
          repository: resolve(alerts.github.repository, 'alerts.github.repository'),
          token: resolve(alerts.github.token, 'alerts.github.token'),
          apiUrl: resolve(alerts.github.apiUrl, 'alerts.github.apiUrl'),
          labels: alerts.github.labels,
          maxIssuesPerRun: alerts.github.maxIssuesPerRun,
        },
        common,
      );
      const detail = `${outcome.created.length} issue(s) created, ${outcome.existing.length} already open${outcome.skipped.length ? `, ${outcome.skipped.length} pending (maxIssuesPerRun or failure)` : ''}`;
      return { delivery: { ids: [...outcome.created, ...outcome.existing], detail, ...(outcome.error ? { error: outcome.error } : {}) }, attempts: 1 };
    }
    case 'teams': {
      const target = { webhookUrl: resolve(alerts.teams.webhookUrl, 'alerts.teams.webhookUrl'), allowInsecureHttp: alerts.teams.allowInsecureHttp };
      // The signature lives in the URL's path/query; an endpoint may echo just that part.
      try {
        const u = new URL(target.webhookUrl);
        secrets.push(u.pathname, u.search, ...u.searchParams.values());
      } catch {
        // An invalid URL is reported by sendTeams.
      }
      const { value, attempts } = await withRetries(() => sendTeams(payload, target, common), alerts.retries, ctx.retryDelayMs);
      return { delivery: { ids: value }, attempts };
    }
    case 'pagerduty': {
      const pd = alerts.pagerduty;
      const target = { routingKey: resolve(pd.routingKey, 'alerts.pagerduty.routingKey'), apiUrl: resolve(pd.apiUrl, 'alerts.pagerduty.apiUrl'), allowInsecureHttp: pd.allowInsecureHttp, maxEventsPerRun: pd.maxEventsPerRun };
      let attempts = 0;
      const retry = async <T>(fn: () => Promise<T>): Promise<T> => {
        const r = await withRetries(fn, alerts.retries, ctx.retryDelayMs).catch((e: unknown) => {
          attempts += (e as { attempts?: number }).attempts ?? 1;
          throw e;
        });
        attempts += r.attempts;
        return r.value;
      };
      const outcome = await sendPagerDuty(payload, target, ctx.resolveIds ?? [], common, retry);
      const detail = outcome.resolved.length ? `${outcome.resolved.length} resolved` : undefined;
      return { delivery: { ids: outcome.triggered, resolved: outcome.resolved, ...(detail ? { detail } : {}), ...(outcome.error ? { error: outcome.error } : {}) }, attempts: Math.max(attempts, 1) };
    }
    case 'email': {
      const port = typeof alerts.email.port === 'number' ? alerts.email.port : Number(resolve(alerts.email.port, 'alerts.email.port'));
      const to = parseRecipients((Array.isArray(alerts.email.to) ? alerts.email.to : [alerts.email.to]).map((t, i) => resolve(t, `alerts.email.to[${i}]`)));
      const target = {
        host: resolve(alerts.email.host, 'alerts.email.host'),
        port,
        secure: alerts.email.secure,
        requireTLS: alerts.email.requireTLS,
        from: resolve(alerts.email.from, 'alerts.email.from'),
        to,
        ...(alerts.email.username ? { username: resolve(alerts.email.username, 'alerts.email.username') } : {}),
        ...(alerts.email.password ? { password: resolve(alerts.email.password, 'alerts.email.password') } : {}),
      };
      const { attempts } = await withRetries(() => sendEmail(payload, target, common), alerts.retries, ctx.retryDelayMs);
      return { delivery: { ids: payload.findings.map((f) => f.id) }, attempts };
    }
  }
}

function errorText(error: unknown, secrets: readonly string[]): string {
  const raw = error instanceof ThirdSentryError || error instanceof Error ? error.message : String(error);
  return redactSecrets(raw, secrets);
}

/** Send one payload through one channel; never throws. */
async function runChannel(channel: ChannelName, payload: AlertPayload, ctx: ChannelContext, selected: number): Promise<{ result: ChannelResult; ids: readonly string[]; resolved: readonly string[] }> {
  const log = getLogger('alerts');
  const secrets: string[] = [];
  try {
    const { delivery, attempts } = await deliver(channel, payload, ctx, secrets);
    const pending = Math.max(0, selected - delivery.ids.length);
    const detailParts = [delivery.detail, !payload.test && pending > 0 ? `${pending} pending for the next run` : undefined].filter(Boolean);
    const detail = detailParts.length ? detailParts.join('; ') : undefined;
    if (delivery.error) {
      const message = errorText(delivery.error, secrets);
      log.error({ channel, delivered: delivery.ids.length, pending, err: message }, 'alert delivery partly failed (scan results are unaffected)');
      return { result: { channel, ok: false, delivered: delivery.ids.length, selected, pending, attempts, ...(detail ? { detail } : {}), error: message }, ids: delivery.ids, resolved: delivery.resolved ?? [] };
    }
    log.info({ channel, findings: delivery.ids.length, pending }, payload.test ? 'test alert delivered' : 'alert delivered');
    return { result: { channel, ok: true, delivered: delivery.ids.length, selected, pending, attempts, ...(detail ? { detail } : {}) }, ids: delivery.ids, resolved: delivery.resolved ?? [] };
  } catch (error) {
    const message = errorText(error, secrets);
    const attempts = (error as { attempts?: number }).attempts ?? 1;
    log.error({ channel, attempts, err: message }, 'alert delivery failed (scan results are unaffected)');
    return { result: { channel, ok: false, delivered: 0, selected, pending: selected, attempts, error: message }, ids: [], resolved: [] };
  }
}

/**
 * PagerDuty autoResolve: findings with an open PagerDuty event that are no
 * longer in the report. Only a COMPLETE scan counts, and only for sites whose
 * own status is complete (the report carries completeness per site, not per
 * page); a partial or failed scan never resolves anything. Suppressed
 * findings count as gone. Marks without a recorded site (older state) are
 * never auto-resolved.
 */
export function findingsToResolve(alerts: AlertsConfig, report: AnalysisReport, state: FindingState): string[] {
  if (!alerts.pagerduty.enabled || !alerts.pagerduty.autoResolve || report.scanStatus !== 'complete') return [];
  const present = new Set(report.findings.filter((f) => !f.suppressed).map((f) => f.id));
  const complete = new Set(report.sites.filter((s) => s.status === 'complete').map((s) => s.name));
  return openAlerts(state, 'pagerduty')
    .filter((o) => o.site !== undefined && complete.has(o.site) && !present.has(o.id))
    .map((o) => o.id);
}

function recoveryNotice(state: FindingState): string | undefined {
  if (!state.recovery) return undefined;
  return `ThirdSentry's alert history was reset on ${state.recovery.at} because the state file was unreadable (moved to ${state.recovery.backup}). Findings below may have been alerted before.`;
}

export async function sendAlerts(resolved: ResolvedConfig, report: AnalysisReport | undefined, options: AlertRunOptions = {}): Promise<AlertRunResult> {
  const log = getLogger('alerts');
  const alerts = resolved.config.alerts;
  const env = options.env ?? process.env;
  const now = options.now ?? new Date();
  const dryRun = options.dryRun === true;
  const test = options.test === true;
  const channels = enabledChannels(alerts, options.channels);
  const base = { dryRun, channels, ...(test ? { test: true } : {}) };
  if (channels.length === 0) return { ...base, selected: 0, results: [] };

  for (const setting of literalSecretWarnings(alerts)) {
    log.warn({ setting }, 'credential is written literally in the configuration; use an ${ENV_VAR} reference instead and keep secrets out of Git');
  }
  const reportLocation = resolveReportLocation(alerts, env, options.reportLocation ?? `${resolved.paths.reports}/report.html`);
  const ctx: ChannelContext = { alerts, env, now, retryDelayMs: options.retryDelayMs ?? 1_000, ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}) };

  if (test) {
    const payload = testPayload(reportLocation, now);
    if (dryRun) return { ...base, selected: 1, results: channels.map((channel) => ({ channel, ok: true, delivered: 0, selected: 1, pending: 1, attempts: 0, detail: 'test alert would be sent' })), payload };
    const results: ChannelResult[] = [];
    for (const channel of channels) results.push((await runChannel(channel, payload, ctx, 1)).result);
    return { ...base, selected: 1, results, payload };
  }
  if (!report) throw new ThirdSentryError('No report to alert on', { hint: 'Run "thirdsentry scan" first.' });

  const state = await loadFindingState(resolved.paths, now);
  const perChannel = new Map<ChannelName, Finding[]>();
  for (const channel of channels) {
    const minSeverity = alerts[channel].minSeverity ?? alerts.minSeverity;
    perChannel.set(channel, selectFindingsForAlert(report, state, { minSeverity, repeatAfterHours: alerts.repeatAfterHours }, now, channel));
  }
  const resolveIds = channels.includes('pagerduty') ? findingsToResolve(alerts, report, state) : [];
  const union = report.findings.filter((f) => [...perChannel.values()].some((list) => list.includes(f)));
  if (union.length === 0 && resolveIds.length === 0) {
    log.info('no new findings at or above the alert thresholds; nothing to send');
    return { ...base, selected: 0, results: [] };
  }
  const notice = recoveryNotice(state);
  const notified = new Set(state.recovery?.notified ?? []);
  const payloadFor = (findings: readonly Finding[], channel?: ChannelName): AlertPayload =>
    buildAlertPayload(report, findings, { maxFindings: channel === 'pagerduty' ? alerts.pagerduty.maxEventsPerRun : alerts.maxFindingsPerAlert, reportLocation, now, ...(notice && !(channel && notified.has(channel)) ? { notice } : {}) });
  const overall = payloadFor(union);

  const results: ChannelResult[] = [];
  if (dryRun) {
    for (const channel of channels) {
      const n = perChannel.get(channel)?.length ?? 0;
      const r = channel === 'pagerduty' ? resolveIds.length : 0;
      const detail = [n ? `${n} finding(s) would be sent` : 'nothing new for this channel', r ? `${r} would be resolved` : undefined].filter(Boolean).join('; ');
      results.push({ channel, ok: true, delivered: 0, selected: n, pending: n, attempts: 0, detail });
    }
    return { ...base, selected: union.length, results, payload: overall };
  }

  const severityOf = (id: string): Severity | undefined => report.findings.find((f) => f.id === id)?.severity;
  const siteOf = (id: string): string | undefined => report.findings.find((f) => f.id === id)?.site;
  let changed = false;
  for (const channel of channels) {
    const selected = perChannel.get(channel) ?? [];
    const resolving = channel === 'pagerduty' ? resolveIds : [];
    if (selected.length === 0 && resolving.length === 0) {
      results.push({ channel, ok: true, delivered: 0, selected: 0, pending: 0, attempts: 0, detail: 'nothing new for this channel' });
      continue;
    }
    const { result, ids, resolved } = await runChannel(channel, payloadFor(selected, channel), { ...ctx, ...(resolving.length ? { resolveIds: resolving } : {}) }, selected.length);
    results.push(result);
    if (ids.length > 0) {
      recordAlerted(state, channel, ids, severityOf, now, siteOf);
      changed = true;
    }
    if (resolved.length > 0) {
      recordResolved(state, channel, resolved, now);
      changed = true;
    }
    if (state.recovery && result.ok && !notified.has(channel)) {
      notified.add(channel);
      state.recovery = { ...state.recovery, notified: [...notified] };
      changed = true;
    }
  }
  if (state.recovery && enabledChannels(alerts).every((c) => notified.has(c))) {
    delete state.recovery;
    changed = true;
  }
  if (changed) await saveFindingState(resolved.paths, state);
  return { ...base, selected: union.length, results, payload: overall };
}
