import nodemailer from 'nodemailer';
import addressparser from 'nodemailer/lib/addressparser';
import { escapeHtml } from '../reporting/html-reporter.js';
import { subjectLine, type AlertPayload } from './alert-payload.js';
import { AlertDeliveryError } from './http.js';

/** E-mail alerts via SMTP (nodemailer). Plain-text and simple HTML bodies; no remote content. */

export interface EmailTarget {
  readonly host: string;
  readonly port: number;
  readonly secure: boolean;
  readonly requireTLS: boolean;
  readonly username?: string;
  readonly password?: string;
  readonly from: string;
  readonly to: readonly EmailAddress[];
}

export interface EmailAddress {
  readonly name: string;
  readonly address: string;
}

/**
 * Parse recipient settings with RFC 5322 address parsing, so display names
 * containing commas (`"Doe, John" <john@example.com>`) and groups work.
 * Each value may hold several comma-separated addresses.
 */
export function parseRecipients(values: readonly string[]): EmailAddress[] {
  const out: EmailAddress[] = [];
  for (const value of values) {
    for (const entry of addressparser(value, { flatten: true })) {
      const address = entry.address.trim();
      if (!/^[^\s@<>]+@[^\s@<>]+$/.test(address)) {
        throw new AlertDeliveryError(`alerts.email.to contains an invalid address${entry.name ? ` (${entry.name})` : ''}`, undefined, false);
      }
      out.push({ name: entry.name, address });
    }
  }
  return out;
}

/**
 * nodemailer error codes / SMTP replies that will not succeed on a retry.
 * Repeating authentication failures in particular can lock the account.
 */
const PERMANENT_SMTP_CODES = new Set(['EAUTH', 'ENOAUTH', 'EOAUTH2', 'EENVELOPE', 'EMESSAGE', 'ETLS', 'EREQUIRETLS', 'EINVALIDCONFIG']);

export function isRetryableSmtpError(error: unknown): boolean {
  const e = error as { code?: unknown; responseCode?: unknown };
  if (typeof e.code === 'string' && PERMANENT_SMTP_CODES.has(e.code)) return false;
  // 5xx replies are permanent failures; 4xx are transient.
  if (typeof e.responseCode === 'number' && e.responseCode >= 500) return false;
  return true;
}

const TEST_TEXT = 'This is a test alert sent by "thirdsentry alert --test" to verify delivery. It is not a real finding.';

export function emailText(payload: AlertPayload): string {
  const lines = [...(payload.test ? [TEST_TEXT, ''] : []), ...(payload.notice ? [`NOTE: ${payload.notice}`, ''] : []), payload.headline, ''];
  for (const f of payload.findings) {
    lines.push(`[${f.severity.toUpperCase()} / confidence ${f.confidence}] ${f.title} (${f.id})`);
    if (f.resourceUrl) lines.push(`  ${f.resourceUrl}`);
    lines.push(`  ${f.reason}`);
    if (f.previousHash !== undefined || f.currentHash !== undefined) lines.push(`  previous ${f.previousHash ?? 'none'}`, `  current  ${f.currentHash ?? 'none'}`);
    lines.push(`  Why: ${f.why}`, `  Next: ${f.recommendedAction}`, '');
  }
  if (payload.omitted > 0) lines.push(`${payload.omitted} more finding(s) are listed in the report.`);
  lines.push(`Scan ${payload.scanId} (${payload.scanStatus}). Report: ${payload.reportLocation}`, '', 'ThirdSentry reports changes worth reviewing; a finding is not proof of compromise.');
  return lines.join('\n');
}

export function emailHtml(payload: AlertPayload): string {
  const e = escapeHtml;
  const items = payload.findings
    .map(
      (f) =>
        `<li><b>${e(f.severity.toUpperCase())}</b> (confidence ${e(f.confidence)}) ${e(f.title)} <code>${e(f.id)}</code>${f.resourceUrl ? `<br><code>${e(f.resourceUrl)}</code>` : ''}<br>${e(f.reason)}<br><small>Why: ${e(f.why)}</small><br><small>Next: ${e(f.recommendedAction)}</small></li>`,
    )
    .join('');
  const intro = `${payload.test ? `<p><b>${e(TEST_TEXT)}</b></p>` : ''}${payload.notice ? `<p><b>Note:</b> ${e(payload.notice)}</p>` : ''}`;
  const more = payload.omitted > 0 ? `<p>${payload.omitted} more finding(s) are listed in the report.</p>` : '';
  return `<!doctype html><html><body>${intro}<p>${e(payload.headline)}</p><ul>${items}</ul>${more}<p><small>Scan ${e(payload.scanId)} (${e(payload.scanStatus)}). Report: ${e(payload.reportLocation)}</small></p></body></html>`;
}

export async function sendEmail(payload: AlertPayload, target: EmailTarget, options: { timeoutMs: number }): Promise<void> {
  if (!Number.isInteger(target.port) || target.port < 1 || target.port > 65535) throw new AlertDeliveryError('alerts.email.port is not a valid port', undefined, false);
  if (target.to.length === 0) throw new AlertDeliveryError('alerts.email.to has no recipients', undefined, false);
  const transport = nodemailer.createTransport({
    host: target.host,
    port: target.port,
    secure: target.secure,
    requireTLS: !target.secure && target.requireTLS,
    connectionTimeout: options.timeoutMs,
    greetingTimeout: options.timeoutMs,
    socketTimeout: options.timeoutMs,
    disableFileAccess: true,
    disableUrlAccess: true,
    ...(target.username ? { auth: { user: target.username, pass: target.password ?? '' } } : {}),
  });
  try {
    await transport.sendMail({ from: target.from, to: target.to.map((t) => ({ name: t.name, address: t.address })), subject: subjectLine(payload), text: emailText(payload), html: emailHtml(payload) });
  } catch (error) {
    const code = typeof (error as { code?: unknown }).code === 'string' ? ` [${(error as { code: string }).code}]` : '';
    throw new AlertDeliveryError(`SMTP delivery failed${code}: ${error instanceof Error ? error.message : String(error)}`, undefined, isRetryableSmtpError(error));
  } finally {
    transport.close();
  }
}
