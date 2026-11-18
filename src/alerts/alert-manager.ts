import type { ResolvedConfig } from '../config/loader.js';
import type { AlertsConfig, Severity } from '../config/schema.js';
import { loadFindingState, recordAlerted, saveFindingState } from '../monitoring/dedup-state.js';
import type { AnalysisReport } from '../types/report.js';
import { ScriptDriftError } from '../utils/errors.js';
import { getLogger } from '../utils/logger.js';
import { buildAlertPayload, filterPayload, selectFindingsForAlert, type AlertPayload } from './alert-payload.js';
import { sendEmail } from './email.js';
import { isLiteralSecret, redactSecrets, resolveEnv } from './env.js';
import { createGithubIssues } from './github-issues.js';
import { AlertDeliveryError, type FetchLike } from './http.js';
import { sendSlack } from './slack.js';
import { sendWebhook } from './webhook.js';

/**
 * Alert publisher. Runs after a report has been written and is the only
 * component that resolves alert credentials. Delivery problems are reported
 * and logged but never affect scan results or reports.
 */

export type ChannelName = 'slack' | 'webhook' | 'github' | 'email';
export const CHANNELS: readonly ChannelName[] = ['slack', 'webhook', 'github', 'email'];

export interface ChannelResult {
  readonly channel: ChannelName;
  readonly ok: boolean;
  readonly delivered: number;
  readonly attempts: number;
  readonly detail?: string;
  readonly error?: string;
}

export interface AlertRunResult {
  readonly selected: number;
  readonly results: readonly ChannelResult[];
  readonly dryRun: boolean;
  readonly payload?: AlertPayload;
}

export interface AlertRunOptions {
  readonly env?: NodeJS.ProcessEnv;
  readonly now?: Date;
  readonly dryRun?: boolean;
  readonly channels?: readonly ChannelName[];
  readonly fetchImpl?: FetchLike;
  /** Base delay between retries (ms); doubled per attempt. */
  readonly retryDelayMs?: number;
  /** Report location to show in alerts (defaults to alerts.reportUrl or the local report path). */
  readonly reportLocation?: string;
}

function enabledChannels(alerts: AlertsConfig, only?: readonly ChannelName[]): ChannelName[] {
  return CHANNELS.filter((c) => alerts[c].enabled && (!only || only.includes(c)));
}

async function withRetries<T>(fn: () => Promise<T>, retries: number, baseDelayMs: number): Promise<{ value: T; attempts: number }> {
  let attempt = 0;
  for (;;) {
    attempt++;
    try {
      return { value: await fn(), attempts: attempt };
    } catch (error) {
      const retryable = !(error instanceof AlertDeliveryError) || error.retryable;
      if (!retryable || attempt > retries) throw Object.assign(error instanceof Error ? error : new Error(String(error)), { attempts: attempt });
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
  return warnings;
}

export async function sendAlerts(resolved: ResolvedConfig, report: AnalysisReport, options: AlertRunOptions = {}): Promise<AlertRunResult> {
  const log = getLogger('alerts');
  const alerts = resolved.config.alerts;
  const env = options.env ?? process.env;
  const now = options.now ?? new Date();
  const channels = enabledChannels(alerts, options.channels);
  if (channels.length === 0) return { selected: 0, results: [], dryRun: options.dryRun === true };

  for (const setting of literalSecretWarnings(alerts)) {
    log.warn({ setting }, 'credential is written literally in the configuration; use an ${ENV_VAR} reference instead and keep secrets out of Git');
  }

  const state = await loadFindingState(resolved.paths);
  const selected = selectFindingsForAlert(report, state, alerts, now);
  if (selected.length === 0) {
    log.info('no new findings at or above the alert threshold; nothing to send');
    return { selected: 0, results: [], dryRun: options.dryRun === true };
  }
  const reportLocation = options.reportLocation ?? (alerts.reportUrl ? resolveEnv(alerts.reportUrl, env, 'alerts.reportUrl') : `${resolved.paths.reports}/report.html`);
  const payload = buildAlertPayload(report, selected, { maxFindings: alerts.maxFindingsPerAlert, reportLocation, now });
  if (options.dryRun) return { selected: selected.length, results: [], dryRun: true, payload };

  const results: ChannelResult[] = [];
  const deliveredIds = new Set<string>();
  for (const channel of channels) {
    const cfg = alerts[channel];
    const scoped = filterPayload(payload, cfg.minSeverity);
    if (!scoped) {
      results.push({ channel, ok: true, delivered: 0, attempts: 0, detail: 'no findings above this channel\'s minSeverity' });
      continue;
    }
    const secrets: string[] = [];
    const resolve = (value: string, setting: string): string => {
      const v = resolveEnv(value, env, setting);
      secrets.push(v);
      return v;
    };
    try {
      const common = { timeoutMs: alerts.timeoutMs, ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}) };
      let detail: string | undefined;
      let deliveredHere = scoped.findings.map((f) => f.id);
      const run = async (): Promise<void> => {
        switch (channel) {
          case 'slack':
            await sendSlack(scoped, resolve(alerts.slack.webhookUrl, 'alerts.slack.webhookUrl'), common);
            break;
          case 'webhook': {
            const secret = alerts.webhook.secret ? resolve(alerts.webhook.secret, 'alerts.webhook.secret') : undefined;
            await sendWebhook(scoped, { url: resolve(alerts.webhook.url, 'alerts.webhook.url'), allowInsecureHttp: alerts.webhook.allowInsecureHttp, ...(secret ? { secret } : {}) }, { ...common, now });
            break;
          }
          case 'github': {
            if (!alerts.github.createIssues) {
              detail = 'createIssues is false';
              deliveredHere = [];
              break;
            }
            const outcome = await createGithubIssues(
              scoped,
              {
                repository: resolve(alerts.github.repository, 'alerts.github.repository'),
                token: resolve(alerts.github.token, 'alerts.github.token'),
                apiUrl: resolve(alerts.github.apiUrl, 'alerts.github.apiUrl'),
                labels: alerts.github.labels,
                maxIssuesPerRun: alerts.github.maxIssuesPerRun,
              },
              common,
            );
            deliveredHere = [...outcome.created, ...outcome.existing];
            detail = `${outcome.created.length} issue(s) created, ${outcome.existing.length} already open${outcome.skipped.length ? `, ${outcome.skipped.length} skipped (maxIssuesPerRun)` : ''}`;
            break;
          }
          case 'email': {
            const port = typeof alerts.email.port === 'number' ? alerts.email.port : Number(resolve(alerts.email.port, 'alerts.email.port'));
            const to = (Array.isArray(alerts.email.to) ? alerts.email.to : [alerts.email.to])
              .map((t, i) => resolve(t, `alerts.email.to[${i}]`))
              .flatMap((t) => t.split(','))
              .map((t) => t.trim())
              .filter(Boolean);
            await sendEmail(
              scoped,
              {
                host: resolve(alerts.email.host, 'alerts.email.host'),
                port,
                secure: alerts.email.secure,
                requireTLS: alerts.email.requireTLS,
                from: resolve(alerts.email.from, 'alerts.email.from'),
                to,
                ...(alerts.email.username ? { username: resolve(alerts.email.username, 'alerts.email.username') } : {}),
                ...(alerts.email.password ? { password: resolve(alerts.email.password, 'alerts.email.password') } : {}),
              },
              common,
            );
            break;
          }
        }
      };
      const { attempts } = await withRetries(run, channel === 'github' ? 0 : alerts.retries, options.retryDelayMs ?? 1_000);
      deliveredHere.forEach((id) => deliveredIds.add(id));
      results.push({ channel, ok: true, delivered: deliveredHere.length, attempts, ...(detail ? { detail } : {}) });
      log.info({ channel, findings: deliveredHere.length }, 'alert delivered');
    } catch (error) {
      const raw = error instanceof ScriptDriftError || error instanceof Error ? error.message : String(error);
      const message = redactSecrets(raw, secrets);
      const attempts = (error as { attempts?: number }).attempts ?? 1;
      results.push({ channel, ok: false, delivered: 0, attempts, error: message });
      log.error({ channel, attempts, err: message }, 'alert delivery failed (scan results are unaffected)');
    }
  }

  if (deliveredIds.size > 0) {
    const severityOf = (id: string): Severity | undefined => report.findings.find((f) => f.id === id)?.severity;
    recordAlerted(state, [...deliveredIds], severityOf, now);
    await saveFindingState(resolved.paths, state);
  }
  return { selected: selected.length, results, dryRun: false, payload };
}
