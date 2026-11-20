import type { AlertPayload } from './alert-payload.js';
import { requireHttpsUrl, sendHttp, type FetchLike } from './http.js';

/** Slack incoming-webhook integration (Block Kit). */

const EMOJI: Record<string, string> = { critical: ':rotating_light:', high: ':red_circle:', medium: ':large_orange_circle:', low: ':large_blue_circle:', info: ':white_circle:' };

/** Slack limits (https://api.slack.com/reference/block-kit/blocks). */
export const SLACK_LIMITS = {
  /** Blocks per message. Above this Slack rejects the whole message (400 invalid_blocks). */
  blocks: 50,
  /** Characters in a section/context text object. */
  sectionText: 3000,
  /** Characters in a header's plain_text. */
  headerText: 150,
  /** Characters used for the top-level notification `text`. */
  text: 3000,
  /**
   * Conservative budget for the combined text of all finding sections, well
   * below Slack's overall message size limit (`msg_too_long`).
   */
  findingsText: 30_000,
} as const;

/** Blocks besides findings: header, notice, summary, "N more findings", footer. */
const FIXED_BLOCKS = 5;
/** Each finding uses a divider and a section. */
const BLOCKS_PER_FINDING = 2;
/** Most findings one Slack message lists individually. */
export const SLACK_MAX_FINDINGS = Math.floor((SLACK_LIMITS.blocks - FIXED_BLOCKS) / BLOCKS_PER_FINDING);

/** Leave headroom below the per-block limit for multi-byte/escaping surprises. */
const SECTION_MAX = SLACK_LIMITS.sectionText - 100;

/** Slack mrkdwn escaping (&, <, >). */
function esc(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function clip(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

export interface SlackMessage {
  readonly body: { text: string; blocks: Array<Record<string, unknown>> };
  /** IDs of the findings individually listed in the message: only these count as delivered. */
  readonly rendered: readonly string[];
}

export function slackMessage(payload: AlertPayload): SlackMessage {
  const total = payload.findings.length + payload.omitted;
  const title = payload.test ? 'ThirdSentry TEST alert (no real finding)' : `ThirdSentry: ${total} finding(s) on ${payload.sites.join(', ')}`;
  const blocks: Array<Record<string, unknown>> = [{ type: 'header', text: { type: 'plain_text', text: clip(title, SLACK_LIMITS.headerText) } }];
  if (payload.notice) blocks.push({ type: 'section', text: { type: 'mrkdwn', text: clip(`:warning: ${esc(payload.notice)}`, SECTION_MAX) } });
  blocks.push({ type: 'section', text: { type: 'mrkdwn', text: clip(esc(payload.headline), SECTION_MAX) } });

  const rendered: string[] = [];
  let budget: number = SLACK_LIMITS.findingsText;
  for (const f of payload.findings) {
    if (rendered.length >= SLACK_MAX_FINDINGS) break;
    const lines = [
      `${EMOJI[f.severity] ?? ''} *${esc(f.severity.toUpperCase())}* (confidence ${esc(f.confidence)}) · *${esc(clip(f.title, 200))}* · \`${esc(f.id)}\``,
      f.resourceUrl ? `\`${esc(clip(f.resourceUrl, 300))}\`` : '',
      esc(clip(f.reason, 900)),
      f.previousHash !== undefined || f.currentHash !== undefined ? `previous \`${f.previousHash ?? 'none'}\`\ncurrent  \`${f.currentHash ?? 'none'}\`` : '',
      `_Why:_ ${esc(clip(f.why, 600))}`,
      `_Next:_ ${esc(clip(f.recommendedAction, 500))}`,
    ].filter(Boolean);
    const text = clip(lines.join('\n'), SECTION_MAX);
    if (text.length > budget) break;
    budget -= text.length;
    blocks.push({ type: 'divider' }, { type: 'section', text: { type: 'mrkdwn', text } });
    rendered.push(f.id);
  }

  const notListed = total - rendered.length;
  if (notListed > 0) {
    blocks.push({ type: 'section', text: { type: 'mrkdwn', text: clip(`*${notListed} more finding(s)* not listed here; they will be listed in a later alert. See the report: ${esc(payload.reportLocation)}`, SECTION_MAX) } });
  }
  const footer = [`Scan \`${esc(payload.scanId)}\` (${esc(payload.scanStatus)})`, `Report: ${esc(payload.reportLocation)}`];
  blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: clip(footer.join(' · '), SECTION_MAX) }] });
  const summary = payload.test ? 'ThirdSentry test alert: delivery to this channel works.' : `ThirdSentry: ${payload.headline}`;
  return { body: { text: clip(summary, SLACK_LIMITS.text), blocks }, rendered };
}

/** Send to Slack. Returns the IDs of the findings listed in the accepted message. */
export async function sendSlack(payload: AlertPayload, webhookUrl: string, options: { timeoutMs: number; fetchImpl?: FetchLike }): Promise<readonly string[]> {
  const url = requireHttpsUrl(webhookUrl, 'alerts.slack.webhookUrl');
  const message = slackMessage(payload);
  await sendHttp({ url: url.toString(), headers: { 'content-type': 'application/json' }, body: JSON.stringify(message.body), timeoutMs: options.timeoutMs }, options.fetchImpl);
  return message.rendered;
}
