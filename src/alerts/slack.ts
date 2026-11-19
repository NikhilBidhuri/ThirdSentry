import type { AlertPayload } from './alert-payload.js';
import { requireHttpsUrl, sendHttp, type FetchLike } from './http.js';

/** Slack incoming-webhook integration (Block Kit). */

const EMOJI: Record<string, string> = { critical: ':rotating_light:', high: ':red_circle:', medium: ':large_orange_circle:', low: ':large_blue_circle:', info: ':white_circle:' };

/** Slack mrkdwn escaping (&, <, >). */
function esc(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function clip(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

export function slackMessage(payload: AlertPayload): Record<string, unknown> {
  const blocks: Array<Record<string, unknown>> = [
    { type: 'header', text: { type: 'plain_text', text: clip(`ThirdSentry: ${payload.findings.length + payload.omitted} finding(s) on ${payload.sites.join(', ')}`, 150) } },
    { type: 'section', text: { type: 'mrkdwn', text: clip(esc(payload.headline), 2900) } },
  ];
  for (const f of payload.findings.slice(0, 40)) {
    const lines = [
      `${EMOJI[f.severity] ?? ''} *${f.severity.toUpperCase()}* (confidence ${f.confidence}) · *${esc(f.title)}* · \`${f.id}\``,
      f.resourceUrl ? `\`${esc(clip(f.resourceUrl, 300))}\`` : '',
      esc(clip(f.reason, 900)),
      f.previousHash !== undefined || f.currentHash !== undefined ? `previous \`${f.previousHash ?? 'none'}\`\ncurrent  \`${f.currentHash ?? 'none'}\`` : '',
      `_Why:_ ${esc(clip(f.why, 600))}`,
      `_Next:_ ${esc(clip(f.recommendedAction, 500))}`,
    ].filter(Boolean);
    blocks.push({ type: 'divider' }, { type: 'section', text: { type: 'mrkdwn', text: clip(lines.join('\n'), 2900) } });
  }
  const footer = [`Scan \`${payload.scanId}\` (${payload.scanStatus})`, `Report: ${esc(payload.reportLocation)}`];
  if (payload.omitted > 0) footer.push(`${payload.omitted} more finding(s) in the report`);
  blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: clip(footer.join(' · '), 2900) }] });
  return { text: clip(`ThirdSentry: ${payload.headline}`, 3000), blocks };
}

export async function sendSlack(payload: AlertPayload, webhookUrl: string, options: { timeoutMs: number; fetchImpl?: FetchLike }): Promise<void> {
  const url = requireHttpsUrl(webhookUrl, 'alerts.slack.webhookUrl');
  await sendHttp({ url: url.toString(), headers: { 'content-type': 'application/json' }, body: JSON.stringify(slackMessage(payload)), timeoutMs: options.timeoutMs }, options.fetchImpl);
}
