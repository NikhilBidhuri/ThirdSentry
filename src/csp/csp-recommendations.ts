/**
 * Explanations and recommendations for every CSP check. Kept separate from
 * the analysis logic so the wording can be reviewed on its own.
 */

export type CspCheckId =
  | 'no-policy'
  | 'report-only'
  | 'missing-default-src'
  | 'no-script-restriction'
  | 'unsafe-inline'
  | 'unsafe-inline-neutralised'
  | 'unsafe-eval'
  | 'wildcard-script-source'
  | 'data-script-source'
  | 'strict-dynamic-without-nonce'
  | 'strict-dynamic-ok'
  | 'allowlist-only'
  | 'risky-script-hosts'
  | 'broad-script-allowlist'
  | 'unsafe-hashes'
  | 'weak-nonce'
  | 'static-nonce'
  | 'object-src'
  | 'missing-base-uri'
  | 'missing-form-action'
  | 'missing-reporting'
  | 'missing-frame-ancestors'
  | 'trusted-types'
  | 'duplicate-directive'
  | 'unknown-directive'
  | 'invalid-source';

export interface Recommendation {
  readonly level: 'error' | 'warning' | 'info';
  readonly title: string;
  readonly explanation: string;
  readonly recommendation: string;
}

export const RECOMMENDATIONS: Record<CspCheckId, Recommendation> = {
  'no-policy': {
    level: 'error',
    title: 'No Content-Security-Policy',
    explanation: 'Without a CSP, any injected script can run and load further code from anywhere.',
    recommendation: "Start with a report-only nonce-based policy, e.g. \"script-src 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; report-to csp\", fix the violations it reports, then enforce it.",
  },
  'report-only': {
    level: 'error',
    title: 'CSP is report-only',
    explanation: 'Content-Security-Policy-Report-Only only reports violations; it does not block anything.',
    recommendation: 'Once the reports are clean, send the same policy as Content-Security-Policy.',
  },
  'missing-default-src': {
    level: 'warning',
    title: 'Missing default-src',
    explanation: 'default-src is the fallback for fetch directives that are not set. Without it, unlisted resource types (fonts, media, connections, ...) are unrestricted.',
    recommendation: "Add a default-src (for example 'self'), then open up specific directives as needed.",
  },
  'no-script-restriction': {
    level: 'error',
    title: 'Scripts are not restricted',
    explanation: 'Neither script-src nor default-src is set, so the policy places no limits on script execution.',
    recommendation: "Add script-src with nonces or hashes and 'strict-dynamic'.",
  },
  'unsafe-inline': {
    level: 'error',
    title: "'unsafe-inline' allows inline scripts",
    explanation: "'unsafe-inline' without a nonce or hash lets any injected inline script or event handler run, which defeats CSP's main protection against XSS.",
    recommendation: "Use nonces or hashes for inline scripts. When a nonce or hash is present, browsers ignore 'unsafe-inline', so it can stay as a fallback for very old browsers.",
  },
  'unsafe-inline-neutralised': {
    level: 'info',
    title: "'unsafe-inline' is ignored because a nonce or hash is present",
    explanation: "Browsers supporting CSP Level 2+ ignore 'unsafe-inline' when the directive also has a nonce or hash. This is a common, intentional backwards-compatibility pattern.",
    recommendation: 'No change needed unless you must support browsers without CSP2.',
  },
  'unsafe-eval': {
    level: 'warning',
    title: "'unsafe-eval' allows string-to-code execution",
    explanation: "'unsafe-eval' permits eval(), new Function() and string timers, which turn data into code and are frequently used by injected payloads.",
    recommendation: "Remove 'unsafe-eval' if possible. If a dependency needs it, isolate that dependency or consider 'wasm-unsafe-eval' when only WebAssembly is involved.",
  },
  'wildcard-script-source': {
    level: 'error',
    title: 'Scripts allowed from any host',
    explanation: "A wildcard (*) or a bare scheme (https:, http:) in the script directive lets scripts load from any server, including an attacker's.",
    recommendation: "Replace the wildcard with nonces/hashes and 'strict-dynamic', or with specific hosts.",
  },
  'data-script-source': {
    level: 'error',
    title: 'data: URLs allowed for scripts',
    explanation: 'Allowing data: in the script directive lets an attacker inline arbitrary code as a data: URL.',
    recommendation: 'Remove data: from script sources.',
  },
  'strict-dynamic-without-nonce': {
    level: 'error',
    title: "'strict-dynamic' without a nonce or hash",
    explanation: "With 'strict-dynamic', host allowlists and 'self' are ignored; only scripts with a matching nonce or hash (and the scripts they load) may run. Without any nonce or hash, no script can bootstrap.",
    recommendation: "Add a per-response nonce to your script tags and to script-src, or remove 'strict-dynamic'.",
  },
  'strict-dynamic-ok': {
    level: 'info',
    title: "'strict-dynamic' is used with nonces/hashes",
    explanation: "This is the recommended modern setup. Scripts trusted via nonce/hash may load further scripts. Host allowlists in the same directive are ignored by CSP3 browsers and only serve as a fallback for older browsers. Note that every script loaded by a trusted script is also trusted, so third-party loaders you trust can still pull in changed code — which is what ScriptDrift monitors.",
    recommendation: 'Keep nonces unpredictable and unique per response.',
  },
  'allowlist-only': {
    level: 'warning',
    title: 'Host allowlist without nonces or hashes',
    explanation: 'Allowlist-based policies are often bypassable through JSONP endpoints, open redirects or user-content hosting on allowed domains.',
    recommendation: "Move to a nonce- or hash-based policy with 'strict-dynamic'.",
  },
  'risky-script-hosts': {
    level: 'warning',
    title: 'Script allowlist includes hosts known to enable CSP bypasses',
    explanation: 'Some allowed hosts serve user-controlled content or JSONP/AngularJS gadgets that let an attacker run code despite the allowlist.',
    recommendation: 'Remove broad shared-hosting or CDN entries, or rely on nonces/hashes instead of host allowlists.',
  },
  'broad-script-allowlist': {
    level: 'warning',
    title: 'Very broad script allowlist',
    explanation: 'Every allowed host is a party that can run code on your pages; long allowlists are hard to review and rarely minimal.',
    recommendation: 'Remove hosts that are no longer used (compare with the scripts ScriptDrift observes) or move to nonces.',
  },
  'unsafe-hashes': {
    level: 'warning',
    title: "'unsafe-hashes' allows hashed inline event handlers",
    explanation: "'unsafe-hashes' permits inline event handlers whose content matches a hash, which keeps an inline-code attack surface.",
    recommendation: 'Move event handlers into script files and use addEventListener.',
  },
  'weak-nonce': {
    level: 'warning',
    title: 'Short nonce',
    explanation: 'Nonces must be unguessable. Short nonces may be brute-forced or indicate a weak generator.',
    recommendation: 'Use at least 128 bits of randomness per response (e.g. 22+ base64 characters).',
  },
  'static-nonce': {
    level: 'error',
    title: 'Nonce does not change between responses',
    explanation: 'A nonce that is reused across responses can be copied by an attacker into injected markup, making the nonce protection useless.',
    recommendation: 'Generate a new random nonce for every response (and make sure caching layers do not cache pages with nonces).',
  },
  'object-src': {
    level: 'error',
    title: "object-src is not 'none'",
    explanation: 'Plugins (<object>, <embed>) can execute code and bypass script restrictions. object-src falls back to default-src, which is often too permissive.',
    recommendation: "Add object-src 'none'.",
  },
  'missing-base-uri': {
    level: 'warning',
    title: 'Missing base-uri',
    explanation: 'base-uri does not fall back to default-src. Without it, an injected <base> tag can redirect relative script URLs to an attacker-controlled host, bypassing nonce-based policies.',
    recommendation: "Add base-uri 'none' (or 'self').",
  },
  'missing-form-action': {
    level: 'warning',
    title: 'Missing form-action',
    explanation: 'form-action does not fall back to default-src, so forms (including injected ones) can submit data to any destination.',
    recommendation: "Add form-action 'self' plus any legitimate external form targets (e.g. a payment provider).",
  },
  'missing-reporting': {
    level: 'warning',
    title: 'No violation reporting',
    explanation: 'Without report-to or report-uri you will not learn about blocked attacks or policy breakage.',
    recommendation: 'Add report-to (with a Reporting-Endpoints header) and/or report-uri.',
  },
  'missing-frame-ancestors': {
    level: 'info',
    title: 'Missing frame-ancestors',
    explanation: 'frame-ancestors controls who may embed your page (clickjacking protection). It does not fall back to default-src. X-Frame-Options may provide the same protection.',
    recommendation: "Add frame-ancestors 'none' or 'self' unless the page must be embeddable.",
  },
  'trusted-types': {
    level: 'info',
    title: 'Trusted Types not required',
    explanation: "require-trusted-types-for 'script' makes DOM XSS sinks (innerHTML, script.src, ...) reject plain strings, which also limits what injected third-party code can do.",
    recommendation: "Consider require-trusted-types-for 'script' in report-only mode first.",
  },
  'duplicate-directive': {
    level: 'warning',
    title: 'Duplicate directive',
    explanation: 'Browsers use only the first occurrence of a directive; later ones are silently ignored, which often means the intended restriction is not applied.',
    recommendation: 'Merge the values into a single directive.',
  },
  'unknown-directive': {
    level: 'warning',
    title: 'Unknown directive',
    explanation: 'Browsers ignore directives they do not recognise; a typo means the intended restriction is missing.',
    recommendation: 'Check the directive name.',
  },
  'invalid-source': {
    level: 'error',
    title: 'Invalid source expression',
    explanation: "Browsers ignore invalid source expressions. A common mistake is an unquoted keyword (self instead of 'self'), which is treated as a hostname.",
    recommendation: 'Fix the source expression.',
  },
};
