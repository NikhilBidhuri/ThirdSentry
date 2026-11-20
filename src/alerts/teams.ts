import type { AlertFinding, AlertPayload } from './alert-payload.js';
import { requireHttpsUrl, sendHttp, type FetchLike } from './http.js';

/**
 * Microsoft Teams through a Workflows (Power Automate) webhook, i.e. the
 * "Post to a channel when a webhook request is received" template. The
 * retired Office 365 connectors (outlook.office.com webhooks) are not used.
 *
 * The body is a `message` with one Adaptive Card attachment (schema 1.4).
 */

export const TEAMS_LIMITS = {
  /** Teams rejects larger request payloads (about 28 KB). */
  maxBytes: 28 * 1024,
  /** Budget we aim for, leaving headroom for envelope differences and multi-byte surprises. */
  targetBytes: 24 * 1024,
} as const;

const COLOR: Record<string, string> = { critical: 'Attention', high: 'Attention', medium: 'Warning', low: 'Accent', info: 'Default' };

/**
 * Neutralise text for an Adaptive Card TextBlock, which renders a markdown
 * subset (bold, italic, lists, links). Markdown punctuation is
 * backslash-escaped, URL schemes and `www.` get a zero-width space so they do
 * not auto-link, `<`/`>` are replaced (no tags or `<at>` mentions) and `@`
 * is broken up (no @-mention look-alikes). Line breaks collapse to spaces.
 */
const ZWSP = String.fromCharCode(0x200b);

export function teamsText(value: string): string {
  return value
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/[\\`*_{}[\]()#+!|~-]/g, '\\$&')
    .replace(/</g, '‹')
    .replace(/>/g, '›')
    .replace(/:\/\//g, `:${ZWSP}//`)
    .replace(/\bwww\./gi, (m) => `${m.slice(0, 3)}${ZWSP}.`)
    .replace(/@/g, `@${ZWSP}`);
}

function clip(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function block(text: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { type: 'TextBlock', text, wrap: true, ...extra };
}

function isHttpUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === 'https:' || u.protocol === 'http:';
  } catch {
    return false;
  }
}

function findingContainer(f: AlertFinding): Record<string, unknown> {
  const items: Array<Record<string, unknown>> = [
    block(`**${teamsText(f.severity.toUpperCase())}** (confidence ${teamsText(f.confidence)}): ${teamsText(clip(f.title, 200))}`, { weight: 'Bolder', color: COLOR[f.severity] ?? 'Default' }),
  ];
  if (f.resourceUrl) items.push(block(teamsText(clip(f.resourceUrl, 300)), { fontType: 'Monospace', size: 'Small', spacing: 'None' }));
  items.push(
    block(teamsText(clip(f.reason, 600)), { spacing: 'Small' }),
    block(`**Why:** ${teamsText(clip(f.why, 400))}`, { size: 'Small', spacing: 'Small' }),
    block(`**Next:** ${teamsText(clip(f.recommendedAction, 300))}`, { size: 'Small', spacing: 'Small' }),
    block(`Finding ID: ${teamsText(f.id)}`, { size: 'Small', isSubtle: true, spacing: 'Small' }),
  );
  return { type: 'Container', style: 'emphasis', separator: true, spacing: 'Medium', items };
}

export interface TeamsMessage {
  readonly body: Record<string, unknown>;
  /** Serialized size in bytes. */
  readonly bytes: number;
  /** IDs of the findings individually rendered: only these count as delivered. */
  readonly rendered: readonly string[];
}

function envelope(card: Record<string, unknown>): Record<string, unknown> {
  return { type: 'message', attachments: [{ contentType: 'application/vnd.microsoft.card.adaptive', contentUrl: null, content: card }] };
}

const size = (body: unknown): number => Buffer.byteLength(JSON.stringify(body), 'utf8');

export function teamsMessage(payload: AlertPayload, maxBytes: number = TEAMS_LIMITS.targetBytes): TeamsMessage {
  const total = payload.findings.length + payload.omitted;
  const title = payload.test ? 'ThirdSentry TEST alert (no real finding)' : `ThirdSentry: ${total} finding(s) on ${payload.sites.join(', ')}`;
  const counts = (['critical', 'high', 'medium', 'low', 'info'] as const).filter((s) => payload.counts[s] > 0).map((s) => `${s} ${payload.counts[s]}`);
  const reportIsUrl = isHttpUrl(payload.reportLocation);

  const build = (n: number): Record<string, unknown> => {
    const body: Array<Record<string, unknown>> = [block(teamsText(clip(title, 200)), { size: 'Large', weight: 'Bolder' })];
    if (payload.notice) body.push(block(`Warning: ${teamsText(clip(payload.notice, 500))}`, { color: 'Warning' }));
    body.push(block(teamsText(clip(payload.headline, 500))));
    if (counts.length > 0 && !payload.test) body.push(block(`By severity: ${counts.join(', ')}`, { isSubtle: true, spacing: 'Small' }));
    for (const f of payload.findings.slice(0, n)) body.push(findingContainer(f));
    const notListed = total - n;
    if (notListed > 0) {
      body.push(block(`**${notListed} more finding(s)** not listed here; they will be listed in a later alert. See the report${reportIsUrl ? '' : `: ${teamsText(payload.reportLocation)}`}.`, { spacing: 'Medium' }));
    }
    body.push(block(`Scan ${teamsText(payload.scanId)} (${teamsText(payload.scanStatus)})${reportIsUrl ? '' : ` · Report: ${teamsText(payload.reportLocation)}`}`, { size: 'Small', isSubtle: true, spacing: 'Medium' }));
    return {
      type: 'AdaptiveCard',
      $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
      version: '1.4',
      msteams: { width: 'Full' },
      body,
      ...(reportIsUrl ? { actions: [{ type: 'Action.OpenUrl', title: 'Open report', url: payload.reportLocation }] } : {}),
    };
  };

  let n = 0;
  while (n < payload.findings.length && size(envelope(build(n + 1))) <= maxBytes) n++;
  const body = envelope(build(n));
  return { body, bytes: size(body), rendered: payload.findings.slice(0, n).map((f) => f.id) };
}

/** Send to Teams. Returns the IDs of the findings rendered in the accepted message. */
export async function sendTeams(payload: AlertPayload, target: { webhookUrl: string; allowInsecureHttp: boolean }, options: { timeoutMs: number; fetchImpl?: FetchLike }): Promise<readonly string[]> {
  const url = requireHttpsUrl(target.webhookUrl, 'alerts.teams.webhookUrl', target.allowInsecureHttp);
  const message = teamsMessage(payload);
  await sendHttp({ url: url.toString(), headers: { 'content-type': 'application/json' }, body: JSON.stringify(message.body), timeoutMs: options.timeoutMs }, options.fetchImpl);
  return message.rendered;
}
