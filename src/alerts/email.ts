import nodemailer from 'nodemailer';
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
  readonly to: readonly string[];
}

export function emailText(payload: AlertPayload): string {
  const lines = [payload.headline, ''];
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
  return `<!doctype html><html><body><p>${e(payload.headline)}</p><ul>${items}</ul><p><small>Scan ${e(payload.scanId)} (${e(payload.scanStatus)}). Report: ${e(payload.reportLocation)}</small></p></body></html>`;
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
    await transport.sendMail({ from: target.from, to: [...target.to], subject: subjectLine(payload), text: emailText(payload), html: emailHtml(payload) });
  } catch (error) {
    throw new AlertDeliveryError(`SMTP delivery failed: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    transport.close();
  }
}
