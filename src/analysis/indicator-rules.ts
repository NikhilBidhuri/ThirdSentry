import type { NodePath } from '@babel/traverse';
import type { Node } from '@babel/types';
import { calleeName, elementKind, entropy, isStringish, lastSegment, memberChain, propertyName, resolvedMemberChain, staticString, stringPrefix, urlHost, type ScopedPath } from './ast-helpers.js';
import type { AnalysisState, Rule } from './rule-types.js';

/**
 * Built-in behaviour-indicator rules.
 *
 * Detection is AST-based (Babel), not regular expressions over source text,
 * so comments and string contents do not trigger code rules and simple
 * whitespace/formatting tricks do not hide them. Static analysis cannot see
 * through runtime-computed property names or code generated at runtime; the
 * dynamic-code and obfuscation rules exist to flag exactly those cases.
 */

const SENSITIVE_FIELD = /password|passwd|pwd|card|cc-?num|ccnum|cc-number|cc-csc|cc-exp|cvv|cvc|csc|security.?code|expir|iban|ssn|social.?security|pin\b|otp/i;
const FORM_FIELD = /\binput\b|select\b|textarea|form\b|\[name=|\[type=|#email|email|phone|address|zip|postal|billing|checkout/i;
const KEY_EVENTS = new Set(['keydown', 'keyup', 'keypress', 'input', 'beforeinput']);
const CLIPBOARD_EVENTS = new Set(['copy', 'cut', 'paste']);
const FORM_EVENTS = new Set(['submit', 'change', 'blur', 'focusout']);
const NETWORK_HOOK_TARGETS = new Set([
  'XMLHttpRequest.prototype.open',
  'XMLHttpRequest.prototype.send',
  'XMLHttpRequest.prototype.setRequestHeader',
  'fetch',
  'navigator.sendBeacon',
  'HTMLFormElement.prototype.submit',
  'WebSocket.prototype.send',
  'EventTarget.prototype.addEventListener',
]);

function firstArg(path: NodePath): Node | undefined {
  const n = path.node;
  if (n.type === 'CallExpression' || n.type === 'NewExpression' || n.type === 'OptionalCallExpression') {
    const a = n.arguments[0];
    return a && a.type !== 'SpreadElement' && a.type !== 'ArgumentPlaceholder' ? a : undefined;
  }
  return undefined;
}

function nthArg(path: NodePath, i: number): Node | undefined {
  const n = path.node;
  if (n.type === 'CallExpression' || n.type === 'NewExpression' || n.type === 'OptionalCallExpression') {
    const a = n.arguments[i];
    return a && a.type !== 'SpreadElement' && a.type !== 'ArgumentPlaceholder' ? a : undefined;
  }
  return undefined;
}

/** True when `name` is not declared in any enclosing scope (Babel counts built-in globals as bindings unless told otherwise). */
function isGlobal(path: NodePath, name: string): boolean {
  return !path.scope.hasBinding(name, { noGlobals: true });
}

/** Callee name with aliased globals resolved (`n.sendBeacon` → `navigator.sendBeacon`). */
function resolvedCallee(path: NodePath): string | undefined {
  const n = path.node;
  if ((n.type === 'CallExpression' || n.type === 'NewExpression') && (n.callee.type === 'MemberExpression' || n.callee.type === 'OptionalMemberExpression')) {
    return resolvedMemberChain(path as unknown as ScopedPath, n.callee);
  }
  return calleeName(n);
}

function resolvedMember(path: NodePath): string | undefined {
  return resolvedMemberChain(path as unknown as ScopedPath, path.node);
}

function recordHost(state: AnalysisState, node: Node | undefined): void {
  const host = urlHost(stringPrefix(node));
  if (host && state.hosts.size < 200) state.hosts.add(host);
}

function isAssignmentTarget(path: NodePath): boolean {
  const parent = path.parentPath;
  return parent?.node.type === 'AssignmentExpression' && parent.node.left === path.node;
}

export const RULES: readonly Rule[] = [
  {
    id: 'SD-EVAL',
    name: 'eval() usage',
    description: 'Code is executed from a string with eval().',
    severity: 'medium',
    confidence: 'high',
    role: 'dynamic-code',
    explanation: 'eval() runs code that is only known at runtime, so the code that actually executes cannot be reviewed from the script itself. Skimmers often decode and eval their payload.',
    investigation: 'Find what string is passed to eval and where it comes from (a constant, a decoded blob, a network response?). Code fetched or decoded at runtime deserves close review.',
    falsePositives: 'Old libraries and some tag managers use eval for JSON parsing or template compilation.',
    visitors: {
      CallExpression(path, state) {
        const name = calleeName(path.node);
        if ((name === 'eval' && isGlobal(path, 'eval')) || name === 'window.eval') state.report('SD-EVAL', path.node);
      },
    },
  },
  {
    id: 'SD-NEW-FUNCTION',
    name: 'Function constructor',
    description: 'Code is compiled from a string with new Function() / Function().',
    severity: 'medium',
    confidence: 'high',
    role: 'dynamic-code',
    explanation: 'Like eval, the Function constructor turns strings into executable code, hiding it from static review.',
    investigation: 'Check the arguments passed to the Function constructor and whether they are constant or derived from decoded or remote data.',
    falsePositives: 'Template engines and some polyfills (e.g. for globalThis detection: Function("return this")()) use it legitimately.',
    visitors: {
      NewExpression(path, state) {
        if (calleeName(path.node) === 'Function' && isGlobal(path, 'Function')) state.report('SD-NEW-FUNCTION', path.node);
      },
      CallExpression(path, state) {
        const n = path.node;
        const name = calleeName(n);
        // x.constructor.constructor(...) reaches Function from any object (common sandbox-escape/obfuscation gadget).
        const gadget =
          n.type === 'CallExpression' &&
          n.callee.type === 'MemberExpression' &&
          propertyName(n.callee) === 'constructor' &&
          n.callee.object.type === 'MemberExpression' &&
          propertyName(n.callee.object) === 'constructor';
        if ((name === 'Function' && isGlobal(path, 'Function')) || gadget) state.report('SD-NEW-FUNCTION', n);
      },
    },
  },
  {
    id: 'SD-STRING-TIMER',
    name: 'String passed to setTimeout/setInterval',
    description: 'A timer is given a string of code instead of a function.',
    severity: 'low',
    confidence: 'high',
    role: 'dynamic-code',
    explanation: 'Timers called with a string evaluate it like eval().',
    investigation: 'Look at the string passed to the timer and where it is built.',
    falsePositives: 'Very old code sometimes uses string timers out of habit.',
    visitors: {
      CallExpression(path, state) {
        const name = lastSegment(calleeName(path.node));
        if ((name === 'setTimeout' || name === 'setInterval') && isStringish(firstArg(path))) state.report('SD-STRING-TIMER', path.node);
      },
    },
  },
  {
    id: 'SD-SCRIPT-INJECTION',
    name: 'Dynamic script injection',
    description: 'The script creates <script> elements or writes script tags into the page.',
    severity: 'low',
    confidence: 'high',
    role: 'loader',
    explanation: 'Injecting scripts lets this code load further code that never appears in your page source. It is how tag managers work, and also how skimmers load their payload.',
    investigation: 'Identify which scripts this code loads (they appear as runtime-injected resources in the scan) and whether they are expected.',
    falsePositives: 'Tag managers, analytics loaders and widget bootstrappers all inject scripts.',
    visitors: {
      CallExpression(path, state) {
        const name = resolvedCallee(path);
        const last = lastSegment(name);
        if (last === 'createElement' || last === 'createElementNS') {
          const arg = staticString(nthArg(path, last === 'createElementNS' ? 1 : 0));
          if (arg?.toLowerCase() === 'script') state.report('SD-SCRIPT-INJECTION', path.node);
        } else if (name === 'document.write' || name === 'document.writeln') {
          const prefix = path.node.type === 'CallExpression' ? path.node.arguments.map((a) => (a.type === 'SpreadElement' || a.type === 'ArgumentPlaceholder' ? '' : (stringPrefix(a) ?? ''))).join('') : '';
          if (/<script/i.test(prefix)) state.report('SD-SCRIPT-INJECTION', path.node, 'document.write');
        } else if (last === 'insertAdjacentHTML' || last === 'createContextualFragment') {
          const html = stringPrefix(nthArg(path, last === 'insertAdjacentHTML' ? 1 : 0));
          if (html && /<script/i.test(html)) state.report('SD-SCRIPT-INJECTION', path.node, last);
        }
      },
    },
  },
  {
    id: 'SD-REMOTE-SCRIPT-LOAD',
    name: 'Loads script from a remote URL',
    description: 'The script loads further code from an absolute URL (script src, importScripts or import()).',
    severity: 'medium',
    confidence: 'medium',
    role: 'loader',
    explanation: 'Remote code loaded at runtime is outside your review and can change at any moment.',
    investigation: 'Check that the referenced host belongs to the expected vendor. Unknown or look-alike domains are a strong warning sign.',
    falsePositives: 'Vendor loaders typically fetch their main bundle from their own CDN.',
    visitors: {
      AssignmentExpression(path, state) {
        const n = path.node;
        if (n.type !== 'AssignmentExpression' || n.left.type !== 'MemberExpression') return;
        if (propertyName(n.left) !== 'src') return;
        if (elementKind(path as unknown as ScopedPath, n.left.object) !== 'script') return;
        const host = urlHost(stringPrefix(n.right));
        if (host) {
          state.report('SD-REMOTE-SCRIPT-LOAD', n, host);
          state.hosts.add(host);
        }
      },
      CallExpression(path, state) {
        const n = path.node;
        const name = calleeName(n);
        if (name === 'importScripts' || (lastSegment(name) === 'setAttribute' && staticString(firstArg(path)) === 'src')) {
          const target = name === 'importScripts' ? firstArg(path) : nthArg(path, 1);
          const host = urlHost(stringPrefix(target));
          if (host) {
            state.report('SD-REMOTE-SCRIPT-LOAD', n, host);
            state.hosts.add(host);
          }
        }
      },
      ImportExpression(path, state) {
        const n = path.node;
        if (n.type !== 'ImportExpression') return;
        const host = urlHost(stringPrefix(n.source));
        if (host) {
          state.report('SD-REMOTE-SCRIPT-LOAD', n, host);
          state.hosts.add(host);
        }
      },
    },
  },
  {
    id: 'SD-COOKIE-ACCESS',
    name: 'document.cookie access',
    description: 'The script reads or writes cookies via document.cookie.',
    severity: 'low',
    confidence: 'high',
    role: 'source',
    explanation: 'Cookies can contain session identifiers. Scripts that read them and send data elsewhere can leak sessions (HttpOnly cookies are not readable).',
    investigation: 'Check which cookies are read and whether their values are sent to another domain.',
    falsePositives: 'Analytics, consent management and A/B testing tools read and write their own cookies.',
    visitors: {
      MemberExpression(path, state) {
        if (resolvedMember(path) === 'document.cookie') state.report('SD-COOKIE-ACCESS', path.node, isAssignmentTarget(path) ? 'write' : 'read');
      },
    },
  },
  {
    id: 'SD-WEB-STORAGE',
    name: 'localStorage/sessionStorage access',
    description: 'The script uses Web Storage.',
    severity: 'info',
    confidence: 'high',
    role: 'source',
    explanation: 'Web Storage can hold tokens or personal data that any script on the page can read.',
    investigation: 'Check which keys are read and whether they belong to this vendor.',
    falsePositives: 'Very common: analytics, consent and personalisation tools persist state this way.',
    visitors: {
      MemberExpression(path, state) {
        // window.localStorage / self.sessionStorage (bare identifiers are handled below).
        const chain = resolvedMember(path);
        if (chain === 'localStorage' || chain === 'sessionStorage') state.report('SD-WEB-STORAGE', path.node, chain);
      },
      Identifier(path, state) {
        const n = path.node;
        if (n.type !== 'Identifier' || (n.name !== 'localStorage' && n.name !== 'sessionStorage')) return;
        const parent = path.parentPath?.node;
        if (parent?.type === 'MemberExpression' && parent.object === n && isGlobal(path, n.name)) state.report('SD-WEB-STORAGE', n, n.name);
      },
    },
  },
  {
    id: 'SD-SENSITIVE-FIELD-ACCESS',
    name: 'Accesses payment or password fields',
    description: 'The script selects form fields whose names suggest passwords, card numbers, CVV or similar.',
    severity: 'high',
    confidence: 'medium',
    role: 'source',
    explanation: 'Reading payment-card or password fields is the core behaviour of form-jacking (Magecart-style) skimmers.',
    investigation: 'Find out why this script needs these fields. Payment providers normally isolate card fields in their own iframe; a third-party script reading card fields on your page is highly unusual.',
    falsePositives: 'Your own checkout code, form validation libraries and payment SDKs that are designed to wrap card inputs.',
    visitors: {
      CallExpression(path, state) {
        const last = lastSegment(calleeName(path.node));
        if (!last || !/^(querySelector|querySelectorAll|getElementById|getElementsByName|getElementsByClassName|closest|matches)$/.test(last)) return;
        const selector = stringPrefix(firstArg(path));
        if (selector && SENSITIVE_FIELD.test(selector)) state.report('SD-SENSITIVE-FIELD-ACCESS', path.node, selector.slice(0, 80));
      },
      StringLiteral(path, state) {
        const n = path.node;
        if (n.type !== 'StringLiteral') return;
        // autocomplete tokens and type selectors in attribute selectors, e.g. 'input[autocomplete="cc-number"]'
        if (/autocomplete\s*[*^$|~]?=\s*["']?cc-|type\s*=\s*["']?password/i.test(n.value)) state.report('SD-SENSITIVE-FIELD-ACCESS', n, n.value.slice(0, 80));
      },
    },
  },
  {
    id: 'SD-FORM-FIELD-ACCESS',
    name: 'Reads form fields',
    description: 'The script selects form inputs or listens to form submission.',
    severity: 'low',
    confidence: 'medium',
    role: 'source',
    explanation: 'Reading form values (names, e-mail, addresses) and sending them elsewhere is how data is skimmed from checkout and login forms.',
    investigation: 'Check which fields are read and where their values go.',
    falsePositives: 'Form analytics, validation, address autocomplete and chat widgets read form fields.',
    visitors: {
      CallExpression(path, state) {
        const name = calleeName(path.node);
        const last = lastSegment(name);
        if (last && /^(querySelector|querySelectorAll|getElementsByTagName)$/.test(last)) {
          const selector = stringPrefix(firstArg(path));
          if (selector && FORM_FIELD.test(selector) && !SENSITIVE_FIELD.test(selector)) state.report('SD-FORM-FIELD-ACCESS', path.node, selector.slice(0, 80));
        }
        if (last === 'addEventListener') {
          const event = staticString(firstArg(path));
          if (event && FORM_EVENTS.has(event)) state.report('SD-FORM-FIELD-ACCESS', path.node, `${event} listener`);
        }
      },
      MemberExpression(path, state) {
        if (resolvedMember(path) === 'document.forms') state.report('SD-FORM-FIELD-ACCESS', path.node, 'document.forms');
      },
    },
  },
  {
    id: 'SD-KEYSTROKE-CAPTURE',
    name: 'Keystroke capture',
    description: 'The script listens to keyboard or input events.',
    severity: 'medium',
    confidence: 'medium',
    role: 'source',
    explanation: 'Listening to every keystroke can capture what users type, including passwords and card numbers, before the form is submitted.',
    investigation: 'Check which element the listener is attached to (document-wide listeners are most concerning) and what is done with the captured keys.',
    falsePositives: 'Keyboard shortcuts, search-as-you-type, accessibility tools and input masking libraries.',
    visitors: {
      CallExpression(path, state) {
        if (lastSegment(calleeName(path.node)) !== 'addEventListener') return;
        const event = staticString(firstArg(path));
        if (event && KEY_EVENTS.has(event)) state.report('SD-KEYSTROKE-CAPTURE', path.node, event);
      },
      AssignmentExpression(path, state) {
        const n = path.node;
        if (n.type !== 'AssignmentExpression' || n.left.type !== 'MemberExpression') return;
        const prop = propertyName(n.left);
        if (prop === 'onkeydown' || prop === 'onkeyup' || prop === 'onkeypress' || prop === 'oninput') state.report('SD-KEYSTROKE-CAPTURE', n, prop);
      },
    },
  },
  {
    id: 'SD-CLIPBOARD',
    name: 'Clipboard access',
    description: 'The script reads or writes the clipboard or listens to copy/paste events.',
    severity: 'medium',
    confidence: 'high',
    role: 'source',
    explanation: 'Clipboard contents can include passwords, card numbers or crypto wallet addresses; clipboard writes can swap pasted values.',
    investigation: 'Check whether the script reads pasted data or replaces copied content.',
    falsePositives: '"Copy to clipboard" buttons and rich-text editors.',
    visitors: {
      MemberExpression(path, state) {
        if (resolvedMember(path) === 'navigator.clipboard' && path.parentPath?.node.type === 'MemberExpression') state.report('SD-CLIPBOARD', path.node);
      },
      CallExpression(path, state) {
        const name = resolvedCallee(path);
        const last = lastSegment(name);
        if (last === 'addEventListener') {
          const event = staticString(firstArg(path));
          if (event && CLIPBOARD_EVENTS.has(event)) state.report('SD-CLIPBOARD', path.node, `${event} listener`);
        } else if (name === 'document.execCommand') {
          const cmd = staticString(firstArg(path))?.toLowerCase();
          if (cmd === 'copy' || cmd === 'paste' || cmd === 'cut') state.report('SD-CLIPBOARD', path.node, `execCommand ${cmd}`);
        }
      },
    },
  },
  {
    id: 'SD-BEACON',
    name: 'navigator.sendBeacon',
    description: 'The script sends data with navigator.sendBeacon.',
    severity: 'low',
    confidence: 'high',
    role: 'sink',
    explanation: 'Beacons send data in the background, even while the page is closing, which makes them convenient for exfiltration.',
    investigation: 'Check the destination URL and what data is sent.',
    falsePositives: 'Analytics and performance monitoring commonly use beacons.',
    visitors: {
      CallExpression(path, state) {
        if (resolvedCallee(path) === 'navigator.sendBeacon') {
          state.report('SD-BEACON', path.node);
          recordHost(state, firstArg(path));
        }
      },
    },
  },
  {
    id: 'SD-WEBSOCKET',
    name: 'WebSocket connection',
    description: 'The script opens a WebSocket connection.',
    severity: 'low',
    confidence: 'high',
    role: 'sink',
    explanation: 'WebSockets provide a persistent two-way channel to a server, which can be used to receive commands or send collected data.',
    investigation: 'Check the WebSocket URL and whether it belongs to the expected vendor.',
    falsePositives: 'Chat widgets, live updates and collaboration tools.',
    visitors: {
      NewExpression(path, state) {
        if (calleeName(path.node) === 'WebSocket' && isGlobal(path, 'WebSocket')) {
          state.report('SD-WEBSOCKET', path.node);
          recordHost(state, firstArg(path));
        }
      },
    },
  },
  {
    id: 'SD-REMOTE-ENDPOINT',
    name: 'Sends requests to absolute URLs',
    description: 'The script calls fetch/XMLHttpRequest or sets image URLs pointing at absolute remote endpoints.',
    severity: 'info',
    confidence: 'medium',
    role: 'sink',
    explanation: 'Requests to remote endpoints are how data leaves the page. On its own this is normal; it matters when combined with access to sensitive data, or when the endpoint is new or unknown.',
    investigation: 'Compare the referenced hosts with the vendors you expect.',
    falsePositives: 'Almost every third-party script talks to its own backend.',
    visitors: {
      CallExpression(path, state) {
        const name = resolvedCallee(path);
        const last = lastSegment(name);
        let target: Node | undefined;
        if ((name === 'fetch' && isGlobal(path, 'fetch')) || name === 'window.fetch') target = firstArg(path);
        else if (last === 'open' && path.node.type === 'CallExpression' && path.node.arguments.length >= 2) {
          const method = staticString(firstArg(path));
          if (method && /^(get|post|put|patch|delete|head)$/i.test(method)) target = nthArg(path, 1);
        }
        if (!target) return;
        const host = urlHost(stringPrefix(target));
        if (host) {
          state.report('SD-REMOTE-ENDPOINT', path.node, host);
          state.hosts.add(host);
        }
      },
      AssignmentExpression(path, state) {
        const n = path.node;
        if (n.type !== 'AssignmentExpression' || n.left.type !== 'MemberExpression' || propertyName(n.left) !== 'src') return;
        // img.src = "https://..." (tracking pixels, and pixel-based exfiltration). Script elements are SD-REMOTE-SCRIPT-LOAD.
        const kind = elementKind(path as unknown as ScopedPath, n.left.object);
        if (kind === 'script') return;
        const host = urlHost(stringPrefix(n.right));
        if (host) {
          state.report('SD-REMOTE-ENDPOINT', n, `${kind ?? 'element'} src ${host}`);
          state.hosts.add(host);
        }
      },
      StringLiteral(path, state) {
        const n = path.node;
        if (n.type !== 'StringLiteral' || n.value.length > 2048) return;
        const host = urlHost(n.value);
        if (host && state.hosts.size < 200) state.hosts.add(host);
      },
    },
  },
  {
    id: 'SD-NETWORK-API-HOOK',
    name: 'Overrides network or form APIs',
    description: 'The script replaces fetch, XMLHttpRequest, sendBeacon, form submission or addEventListener.',
    severity: 'medium',
    confidence: 'high',
    role: 'hooking',
    explanation: 'Wrapping network or form APIs lets a script see (and alter) every request and form submission on the page, including those of other scripts.',
    investigation: 'Determine why the script needs to intercept other code\'s requests. Monitoring tools do this; so do skimmers.',
    falsePositives: 'Real-user-monitoring, error tracking and some analytics SDKs instrument fetch/XHR.',
    visitors: {
      AssignmentExpression(path, state) {
        const n = path.node;
        if (n.type !== 'AssignmentExpression') return;
        const target = n.left.type === 'MemberExpression' ? memberChain(n.left) : n.left.type === 'Identifier' ? n.left.name : undefined;
        if (target && NETWORK_HOOK_TARGETS.has(target) && (n.left.type !== 'Identifier' || isGlobal(path, n.left.name))) {
          state.report('SD-NETWORK-API-HOOK', n, target);
        }
      },
    },
  },
  {
    id: 'SD-OBFUSCATION',
    name: 'Obfuscated or heavily encoded code',
    description: 'The script shows several signs of deliberate obfuscation.',
    severity: 'medium',
    confidence: 'medium',
    role: 'obfuscation',
    explanation: 'Obfuscation hides what code does. Legitimate vendors usually minify, but rarely obfuscate with encoded string tables, hex-named variables and runtime decoding.',
    investigation: 'Try a deobfuscator or beautifier on the retained content, look for decoded URLs and eval/Function usage, and ask the vendor why the code is obfuscated.',
    falsePositives: 'Some commercial anti-fraud, bot-detection and licensing scripts are obfuscated on purpose.',
    visitors: {
      Identifier(path, state) {
        const n = path.node;
        if (n.type === 'Identifier' && /^_0x[0-9a-f]{3,}$/i.test(n.name)) state.scratch.set('hexIdent', (state.scratch.get('hexIdent') ?? 0) + 1);
      },
      StringLiteral(path, state) {
        const n = path.node;
        if (n.type !== 'StringLiteral') return;
        const raw = (n.extra?.raw as string | undefined) ?? '';
        const escapes = (raw.match(/\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/gi) ?? []).length;
        if (escapes >= 4 && escapes * 4 >= raw.length * 0.5) state.scratch.set('escapedStrings', (state.scratch.get('escapedStrings') ?? 0) + 1);
        if (n.value.length >= 200 && /^[A-Za-z0-9+/=]+$/.test(n.value) && entropy(n.value) > 5.2) {
          state.scratch.set('encodedBlobs', (state.scratch.get('encodedBlobs') ?? 0) + 1);
        }
      },
      CallExpression(path, state) {
        const name = calleeName(path.node);
        if ((name === 'atob' && isGlobal(path, 'atob')) || name === 'window.atob') state.scratch.set('atob', (state.scratch.get('atob') ?? 0) + 1);
        if (name === 'String.fromCharCode' && path.node.type === 'CallExpression' && path.node.arguments.length >= 8) {
          state.scratch.set('charCodes', (state.scratch.get('charCodes') ?? 0) + 1);
        }
        if (lastSegment(name) === 'unescape' || lastSegment(name) === 'decodeURIComponent') {
          if (staticString(firstArg(path))?.includes('%')) state.scratch.set('unescape', (state.scratch.get('unescape') ?? 0) + 1);
        }
      },
      ArrayExpression(path, state) {
        const n = path.node;
        if (n.type === 'ArrayExpression' && n.elements.length >= 50 && n.elements.every((e) => e?.type === 'StringLiteral')) {
          state.scratch.set('stringTables', (state.scratch.get('stringTables') ?? 0) + 1);
        }
      },
    },
    finalize(state, ast) {
      const s = (k: string): number => state.scratch.get(k) ?? 0;
      const indicators: string[] = [];
      if (s('hexIdent') >= 20) indicators.push(`${s('hexIdent')} hex-named identifiers (_0x…)`);
      if (s('escapedStrings') >= 10) indicators.push(`${s('escapedStrings')} hex/unicode-escaped strings`);
      if (s('encodedBlobs') >= 1) indicators.push(`${s('encodedBlobs')} long high-entropy encoded string(s)`);
      if (s('atob') >= 3) indicators.push(`${s('atob')} atob() decode calls`);
      if (s('charCodes') >= 2) indicators.push(`${s('charCodes')} String.fromCharCode() calls building strings`);
      if (s('stringTables') >= 1) indicators.push('large string lookup table');
      if (s('unescape') >= 2) indicators.push('percent-decoding of embedded strings');
      // Require several independent signals so that ordinary minified code does not match.
      if (indicators.length >= 2) state.report('SD-OBFUSCATION', ast, indicators.join('; '));
    },
  },
  {
    id: 'SD-EXFIL-COMBINATION',
    name: 'Sensitive data access combined with data transmission',
    description: 'The same script both reads sensitive input (form fields, keystrokes, clipboard) and sends data to remote endpoints.',
    severity: 'high',
    confidence: 'medium',
    role: 'combination',
    explanation: 'Each behaviour alone is common. Together, reading what users type and sending data elsewhere is the pattern of a data skimmer.',
    investigation: 'Trace whether values read from inputs flow into the outgoing requests. Check the destination hosts. On payment or login pages, treat this as urgent until explained.',
    falsePositives: 'Form analytics and session-replay tools legitimately capture input (often masked) and upload it. Verify the vendor and its masking configuration.',
    finalize(state, ast) {
      const has = (id: string): boolean => (state.counts.get(id) ?? 0) > 0;
      const sources = ['SD-SENSITIVE-FIELD-ACCESS', 'SD-KEYSTROKE-CAPTURE', 'SD-CLIPBOARD', 'SD-FORM-FIELD-ACCESS'].filter(has);
      const sinks = ['SD-BEACON', 'SD-WEBSOCKET', 'SD-REMOTE-ENDPOINT', 'SD-NETWORK-API-HOOK'].filter(has);
      const strongSource = sources.some((s) => s !== 'SD-FORM-FIELD-ACCESS');
      if (sources.length > 0 && sinks.length > 0 && (strongSource || has('SD-NETWORK-API-HOOK'))) {
        state.report('SD-EXFIL-COMBINATION', ast, `sources: ${sources.join(', ')}; sinks: ${sinks.join(', ')}`);
      }
    },
  },
];

export const RULES_BY_ID: ReadonlyMap<string, Rule> = new Map(RULES.map((r) => [r.id, r]));
