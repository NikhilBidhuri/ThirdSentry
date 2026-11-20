/**
 * Redaction helpers. ThirdSentry stores *metadata* about third-party
 * resources; it must never persist cookies, authorization headers, session
 * tokens or request bodies. Header storage is allowlist-based: anything not
 * explicitly known to be harmless is dropped.
 */

const STORED_RESPONSE_HEADERS = new Set([
  'access-control-allow-origin',
  'age',
  'cache-control',
  'cf-cache-status',
  'content-encoding',
  'content-length',
  'content-security-policy',
  'content-security-policy-report-only',
  'content-type',
  'cross-origin-embedder-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'date',
  'etag',
  'expires',
  'last-modified',
  'location',
  'permissions-policy', // security headers of documents (PCI DSS 11.6.1 header baselines)
  'referrer-policy',
  'server',
  'service-worker-allowed',
  'strict-transport-security',
  'timing-allow-origin',
  'via',
  'x-cache',
  'x-content-type-options',
  'x-frame-options',
]);

const STORED_REQUEST_HEADERS = new Set(['accept', 'referer', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'purpose']);

export const REDACTED = '[REDACTED]';

const MAX_HEADER_VALUE = 2048;

function filterHeaders(headers: Readonly<Record<string, string>>, allow: ReadonlySet<string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [rawKey, value] of Object.entries(headers)) {
    const key = rawKey.toLowerCase();
    if (!allow.has(key)) continue;
    let v = value.length > MAX_HEADER_VALUE ? `${value.slice(0, MAX_HEADER_VALUE)}…[truncated]` : value;
    if (key === 'location' || key === 'referer') v = redactUrl(v);
    out[key] = v;
  }
  return out;
}

export function filterResponseHeaders(headers: Readonly<Record<string, string>>): Record<string, string> {
  return filterHeaders(headers, STORED_RESPONSE_HEADERS);
}

export function filterRequestHeaders(headers: Readonly<Record<string, string>>): Record<string, string> {
  return filterHeaders(headers, STORED_REQUEST_HEADERS);
}

/** Query-parameter names whose values are likely to carry secrets or personal data. */
const SENSITIVE_PARAM =
  /(^|[_-])(token|access_token|id_token|refresh_token|secret|password|passwd|pwd|pass|session|sessionid|sess|sid|auth|authorization|apikey|api_key|key|signature|sig|code|otp|email|e-mail|mail|phone|tel|card|cc|ccnum|cvv|cvc|ssn|jwt|bearer|credential|creds?)([_-]|$)/i;

export function isSensitiveParam(name: string): boolean {
  return SENSITIVE_PARAM.test(name);
}

const MAX_URL_LENGTH = 4096;

/**
 * Redact values of sensitive-looking query parameters and strip URL
 * credentials and fragments. Parameter *names* are kept so that changes in
 * request shape remain visible. Non-URL strings are returned truncated.
 */
export function redactUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return raw.length > MAX_URL_LENGTH ? `${raw.slice(0, MAX_URL_LENGTH)}…[truncated]` : raw;
  }
  if (url.protocol === 'data:') {
    return `data:${raw.slice(5, 60).split(',')[0] ?? ''},…[data URL omitted]`;
  }
  if (url.username || url.password) {
    url.username = '';
    url.password = '';
  }
  url.hash = '';
  if (url.search) {
    const params = new URLSearchParams(url.search);
    const redacted = new URLSearchParams();
    for (const [key, value] of params) redacted.append(key, isSensitiveParam(key) && value ? REDACTED : value);
    url.search = redacted.toString();
  }
  const out = url.toString();
  return out.length > MAX_URL_LENGTH ? `${out.slice(0, MAX_URL_LENGTH)}…[truncated]` : out;
}

/** Truncate free-form text (console messages, error strings) and strip obvious bearer tokens. */
export function redactText(text: string, max = 1000): string {
  const cleaned = text
    .replace(/bearer\s+[a-z0-9._~+/=-]{8,}/gi, `Bearer ${REDACTED}`)
    .replace(/eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g, REDACTED);
  return cleaned.length > max ? `${cleaned.slice(0, max)}…[truncated]` : cleaned;
}
