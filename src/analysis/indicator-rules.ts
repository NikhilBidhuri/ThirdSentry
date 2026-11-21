import type { NodePath } from '@babel/traverse';
import type { Node } from '@babel/types';
import {
  callArguments,
  calleeName,
  calleeOf,
  elementKind,
  entropy,
  foldString,
  isStringish,
  lastSegment,
  memberChain,
  propertyName,
  resolveName,
  resolvedMemberChain,
  scopedPropertyName,
  staticString,
  stringPrefix,
  urlHost,
} from './ast-helpers.js';
import type { AnalysisState, Rule } from './rule-types.js';

/**
 * Built-in behaviour-indicator rules.
 *
 * Detection is AST-based (Babel), not regular expressions over source text,
 * so comments and string contents do not trigger code rules and simple
 * whitespace/formatting tricks do not hide them. Call-like rules see plain
 * calls, optional calls (`f?.()`), `new` and tagged templates (`` f`x` ``);
 * names are resolved through constant-folded computed members
 * (`window['ev' + 'al']`) and simple aliases (`var e = eval`). Static
 * analysis still cannot see through property names computed at runtime or
 * code generated at runtime; the dynamic-code and obfuscation rules exist to
 * flag exactly those cases.
 */

const SENSITIVE_FIELD = /password|passwd|pwd|card|cc-?num|ccnum|cc-number|cc-csc|cc-exp|cvv|cvc|csc|security.?code|expir|iban|ssn|social.?security|pin\b|otp/i;
const FORM_FIELD = /\binput\b|select\b|textarea|form\b|\[name=|\[type=|#email|email|phone|address|zip|postal|billing|checkout/i;
const KEY_EVENTS = new Set(['keydown', 'keyup', 'keypress', 'input', 'beforeinput']);
const CLIPBOARD_EVENTS = new Set(['copy', 'cut', 'paste']);
const FORM_EVENTS = new Set(['submit', 'change', 'blur', 'focusout']);
const NETWORK_HOOK_TARGETS = new Set([
  'XMLHttpRequest',
  'XMLHttpRequest.prototype.open',
  'XMLHttpRequest.prototype.send',
  'XMLHttpRequest.prototype.setRequestHeader',
  'fetch',
  'navigator.sendBeacon',
  'Navigator.prototype.sendBeacon',
  'HTMLFormElement.prototype.submit',
  'WebSocket',
  'WebSocket.prototype.send',
  'EventTarget.prototype.addEventListener',
]);
/** Calls that define or overwrite a property: (target, name, …) or (target, { name: … }). */
const PROPERTY_DEFINERS = new Set(['Object.defineProperty', 'Reflect.defineProperty', 'Reflect.set', 'Object.defineProperties', 'Object.assign']);
/** Globals that are functions, so `<global>.constructor` is the Function constructor. */
const GLOBAL_FUNCTIONS = new Set([
  'Function', 'eval', 'alert', 'Object', 'Array', 'String', 'Number', 'Boolean', 'Symbol', 'Date', 'RegExp', 'Error', 'Promise', 'Map', 'Set',
  'parseInt', 'parseFloat', 'escape', 'unescape', 'atob', 'btoa', 'fetch', 'setTimeout', 'setInterval', 'isNaN', 'isFinite',
  'encodeURI', 'decodeURI', 'encodeURIComponent', 'decodeURIComponent', 'Function.prototype',
]);
/** Property names that are (almost always) built-in methods, so `x.<name>.constructor` is Function. */
const METHOD_NAMES = new Set([
  'filter', 'map', 'forEach', 'reduce', 'some', 'every', 'find', 'findIndex', 'indexOf', 'join', 'push', 'pop', 'slice', 'splice', 'concat',
  'call', 'apply', 'bind', 'toString', 'valueOf', 'hasOwnProperty', 'fill', 'at', 'includes', 'keys', 'entries', 'values', 'sort', 'reverse',
  'shift', 'unshift', 'flat', 'flatMap', 'trim', 'split', 'replace', 'charAt', 'charCodeAt', 'fromCharCode', 'sub', 'big', 'bold', 'italics',
  'link', 'small', 'strike', 'sup', 'anchor', 'fontcolor', 'blink', 'constructor',
]);
const SOURCE_TEXT_PROPS = new Set(['text', 'textContent', 'innerHTML', 'innerText', 'outerHTML']);
const GLOBAL_OBJECTS = new Set(['window', 'self', 'globalThis', 'top', 'parent', 'frames']);

/** An invocation (call, optional call, `new`, tagged template) with its callee names and effective arguments. */
interface Invocation {
  readonly node: Node;
  readonly args: Node[];
  readonly tagged: boolean;
  readonly isNew: boolean;
  /** Callee chain as written (computed names folded), e.g. `el.querySelector`. */
  readonly raw: string | undefined;
  /** Callee resolved through aliases to a global, e.g. `eval` for `var e = eval; e(…)`; `.call`/`.apply` stripped. */
  readonly resolved: string | undefined;
  /** Resolved name, else the raw name. */
  readonly name: string | undefined;
}

function invocation(path: NodePath): Invocation {
  const node = path.node;
  const callee = calleeOf(node);
  let args = callArguments(node);
  const raw = calleeName(node);
  let resolved = callee ? resolveName(path, callee) : undefined;
  // f.call(thisArg, a, b) / f.apply(thisArg, [a, b]) invoke f.
  const via = /\.(call|apply)$/.exec(resolved ?? '');
  if (resolved && via) {
    resolved = resolved.slice(0, -via[0].length);
    const rest = args.slice(1);
    const list = rest[0];
    args = via[1] === 'apply' ? (list?.type === 'ArrayExpression' ? list.elements.filter((e): e is NonNullable<typeof e> => e !== null && e.type !== 'SpreadElement') : []) : rest;
  }
  return { node, args, tagged: node.type === 'TaggedTemplateExpression', isNew: node.type === 'NewExpression', raw, resolved, name: resolved ?? raw };
}

function recordHost(state: AnalysisState, node: Node | undefined): void {
  const host = urlHost(stringPrefix(node));
  if (host && state.hosts.size < 200) state.hosts.add(host);
}

function isAssignmentTarget(path: NodePath): boolean {
  const parent = path.parentPath;
  return parent?.node.type === 'AssignmentExpression' && parent.node.left === path.node;
}

function resolvedMember(path: NodePath): string | undefined {
  return resolvedMemberChain(path, path.node);
}

/** True when the expression evaluates to a function (so its `.constructor` is a Function constructor). */
function isFunctionValued(path: NodePath, node: Node, depth = 0): boolean {
  if (depth > 4) return false;
  switch (node.type) {
    case 'FunctionExpression':
    case 'ArrowFunctionExpression':
    case 'ClassExpression':
      return true;
    case 'MemberExpression':
    case 'OptionalMemberExpression': {
      const prop = scopedPropertyName(path, node);
      if (prop !== undefined && METHOD_NAMES.has(prop)) return true;
      const name = resolveName(path, node);
      return name !== undefined && GLOBAL_FUNCTIONS.has(name);
    }
    case 'Identifier': {
      const binding = path.scope.getBinding(node.name);
      if (!binding) return GLOBAL_FUNCTIONS.has(node.name);
      const decl = binding.path.node;
      if (decl.type === 'FunctionDeclaration' || decl.type === 'ClassDeclaration') return true;
      if (decl.type === 'VariableDeclarator' && decl.init) return isFunctionValued(binding.path, decl.init, depth + 1);
      return false;
    }
    default:
      return false;
  }
}

/** `<function>.constructor(…)` reaches the Function (or AsyncFunction/GeneratorFunction) constructor from any function value. */
function isConstructorGadget(path: NodePath, node: Node): boolean {
  const callee = calleeOf(node);
  if (!callee || (callee.type !== 'MemberExpression' && callee.type !== 'OptionalMemberExpression')) return false;
  if (scopedPropertyName(path, callee) !== 'constructor') return false;
  return isFunctionValued(path, callee.object);
}

/** Dotted name of `<target>.<prop>` with global objects removed (`window` + `fetch` → `fetch`). */
function joinTarget(target: string | undefined, prop: string | undefined): string | undefined {
  if (target === undefined || prop === undefined) return undefined;
  return GLOBAL_OBJECTS.has(target) ? prop : `${target}.${prop}`;
}

/** Global names defined by Object.defineProperty / defineProperties / assign / Reflect.set / Reflect.defineProperty calls. */
function definedProperties(path: NodePath, inv: Invocation): string[] {
  const [target, second] = inv.args;
  if (!target) return [];
  const targetName = resolveName(path, target) ?? memberChain(target);
  if (inv.resolved === 'Object.defineProperties' || inv.resolved === 'Object.assign') {
    if (second?.type !== 'ObjectExpression') return [];
    const out: string[] = [];
    for (const p of second.properties) {
      if (p.type !== 'ObjectProperty' && p.type !== 'ObjectMethod') continue;
      const key = !p.computed && p.key.type === 'Identifier' ? p.key.name : foldString(path, p.key);
      const name = joinTarget(targetName, key);
      if (name) out.push(name);
    }
    return out;
  }
  const name = joinTarget(targetName, foldString(path, second));
  return name ? [name] : [];
}

/** TS-NEW-FUNCTION for `new Function`, `Function(…)`, `Function?.(…)`, `` Function`…` ``, aliases and `.constructor` gadgets. */
function reportFunctionConstructor(path: NodePath, state: AnalysisState): void {
  const inv = invocation(path);
  if (inv.resolved === 'Function' || inv.resolved === 'Function.prototype.constructor') {
    state.report('TS-NEW-FUNCTION', path.node, inv.raw === 'Function' ? undefined : `via ${inv.raw ?? 'indirect reference'}`);
  } else if (isConstructorGadget(path, path.node)) {
    state.report('TS-NEW-FUNCTION', path.node, 'constructor gadget');
  }
}

/** True when `name` is not declared in any enclosing scope (Babel counts built-in globals as bindings unless told otherwise). */
function isGlobal(path: NodePath, name: string): boolean {
  return !path.scope.hasBinding(name, { noGlobals: true });
}

/** Function bound to an identifier or written inline (for `fn.toString()` reflection). */
function isFunctionLiteralOrBinding(path: NodePath, node: Node): boolean {
  if (node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression' || node.type === 'ClassExpression') return true;
  if (node.type === 'MemberExpression' && memberChain(node) === 'arguments.callee') return true;
  if (node.type !== 'Identifier') return false;
  const decl = path.scope.getBinding(node.name)?.path.node;
  if (!decl) return false;
  if (decl.type === 'FunctionDeclaration' || decl.type === 'ClassDeclaration') return true;
  return decl.type === 'VariableDeclarator' && (decl.init?.type === 'FunctionExpression' || decl.init?.type === 'ArrowFunctionExpression' || decl.init?.type === 'ClassExpression');
}

export const RULES: readonly Rule[] = [
  {
    id: 'TS-EVAL',
    name: 'eval() usage',
    description: 'Code is executed from a string with eval().',
    severity: 'medium',
    confidence: 'high',
    role: 'dynamic-code',
    explanation: 'eval() runs code that is only known at runtime, so the code that actually executes cannot be reviewed from the script itself. Skimmers often decode and eval their payload.',
    investigation: 'Find what string is passed to eval and where it comes from (a constant, a decoded blob, a network response?). Code fetched or decoded at runtime deserves close review.',
    falsePositives: 'Old libraries and some tag managers use eval for JSON parsing or template compilation.',
    visitors: {
      // Also optional calls (eval?.(x)), aliases (var e = eval), computed names (window['ev' + 'al']) and eval.call(…).
      CallExpression(path, state) {
        const inv = invocation(path);
        if (!inv.tagged && inv.resolved === 'eval') state.report('TS-EVAL', path.node, inv.raw === 'eval' ? undefined : `via ${inv.raw ?? 'indirect reference'}`);
      },
    },
  },
  {
    id: 'TS-NEW-FUNCTION',
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
        reportFunctionConstructor(path, state);
      },
      // Also Function?.(x), Function`code`, aliases, and <any function>.constructor(…) gadgets such as
      // (function(){}).constructor(x) or []['filter']['constructor'](x).
      CallExpression(path, state) {
        reportFunctionConstructor(path, state);
      },
    },
  },
  {
    id: 'TS-STRING-TIMER',
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
        const inv = invocation(path);
        const name = lastSegment(inv.name);
        // setTimeout`code` passes the template strings, which are converted to a string and evaluated.
        if ((name === 'setTimeout' || name === 'setInterval') && (inv.tagged || isStringish(inv.args[0]))) state.report('TS-STRING-TIMER', path.node);
      },
    },
  },
  {
    id: 'TS-SCRIPT-INJECTION',
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
        const inv = invocation(path);
        const name = inv.name;
        const last = lastSegment(name);
        if (last === 'createElement' || last === 'createElementNS') {
          const arg = foldString(path, inv.args[last === 'createElementNS' ? 1 : 0]);
          if (arg?.toLowerCase() === 'script') state.report('TS-SCRIPT-INJECTION', path.node);
        } else if (name === 'document.write' || name === 'document.writeln') {
          const prefix = inv.args.map((a) => stringPrefix(a) ?? '').join('');
          if (/<script/i.test(prefix)) state.report('TS-SCRIPT-INJECTION', path.node, 'document.write');
        } else if (last === 'insertAdjacentHTML' || last === 'createContextualFragment') {
          const html = stringPrefix(inv.args[last === 'insertAdjacentHTML' ? 1 : 0]);
          if (html && /<script/i.test(html)) state.report('TS-SCRIPT-INJECTION', path.node, last);
        }
      },
    },
  },
  {
    id: 'TS-REMOTE-SCRIPT-LOAD',
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
        if (elementKind(path, n.left.object) !== 'script') return;
        const host = urlHost(stringPrefix(n.right));
        if (host) {
          state.report('TS-REMOTE-SCRIPT-LOAD', n, host);
          state.hosts.add(host);
        }
      },
      CallExpression(path, state) {
        const n = path.node;
        const inv = invocation(path);
        const name = inv.name;
        if (name === 'importScripts' || (lastSegment(name) === 'setAttribute' && foldString(path, inv.args[0]) === 'src')) {
          const target = name === 'importScripts' ? inv.args[0] : inv.args[1];
          const host = urlHost(stringPrefix(target));
          if (host) {
            state.report('TS-REMOTE-SCRIPT-LOAD', n, host);
            state.hosts.add(host);
          }
        }
      },
      ImportExpression(path, state) {
        const n = path.node;
        if (n.type !== 'ImportExpression') return;
        const host = urlHost(stringPrefix(n.source));
        if (host) {
          state.report('TS-REMOTE-SCRIPT-LOAD', n, host);
          state.hosts.add(host);
        }
      },
    },
  },
  {
    id: 'TS-COOKIE-ACCESS',
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
        if (resolvedMember(path) === 'document.cookie') state.report('TS-COOKIE-ACCESS', path.node, isAssignmentTarget(path) ? 'write' : 'read');
      },
    },
  },
  {
    id: 'TS-WEB-STORAGE',
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
        if (chain === 'localStorage' || chain === 'sessionStorage') state.report('TS-WEB-STORAGE', path.node, chain);
      },
      Identifier(path, state) {
        const n = path.node;
        if (n.type !== 'Identifier' || (n.name !== 'localStorage' && n.name !== 'sessionStorage')) return;
        const parent = path.parentPath?.node;
        if ((parent?.type === 'MemberExpression' || parent?.type === 'OptionalMemberExpression') && parent.object === n && isGlobal(path, n.name)) state.report('TS-WEB-STORAGE', n, n.name);
      },
    },
  },
  {
    id: 'TS-SENSITIVE-FIELD-ACCESS',
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
        const inv = invocation(path);
        const last = lastSegment(inv.raw ?? inv.name);
        if (!last || !/^(querySelector|querySelectorAll|getElementById|getElementsByName|getElementsByClassName|closest|matches)$/.test(last)) return;
        const selector = foldString(path, inv.args[0]) ?? stringPrefix(inv.args[0]);
        if (selector && SENSITIVE_FIELD.test(selector)) state.report('TS-SENSITIVE-FIELD-ACCESS', path.node, selector.slice(0, 80));
      },
      StringLiteral(path, state) {
        const n = path.node;
        if (n.type !== 'StringLiteral') return;
        // autocomplete tokens and type selectors in attribute selectors, e.g. 'input[autocomplete="cc-number"]'
        if (/autocomplete\s*[*^$|~]?=\s*["']?cc-|type\s*=\s*["']?password/i.test(n.value)) state.report('TS-SENSITIVE-FIELD-ACCESS', n, n.value.slice(0, 80));
      },
    },
  },
  {
    id: 'TS-FORM-FIELD-ACCESS',
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
        const inv = invocation(path);
        const last = lastSegment(inv.raw ?? inv.name);
        if (last && /^(querySelector|querySelectorAll|getElementsByTagName)$/.test(last)) {
          const selector = foldString(path, inv.args[0]) ?? stringPrefix(inv.args[0]);
          if (selector && FORM_FIELD.test(selector) && !SENSITIVE_FIELD.test(selector)) state.report('TS-FORM-FIELD-ACCESS', path.node, selector.slice(0, 80));
        }
        if (last === 'addEventListener') {
          const event = foldString(path, inv.args[0]);
          if (event && FORM_EVENTS.has(event)) state.report('TS-FORM-FIELD-ACCESS', path.node, `${event} listener`);
        }
      },
      MemberExpression(path, state) {
        if (resolvedMember(path) === 'document.forms') state.report('TS-FORM-FIELD-ACCESS', path.node, 'document.forms');
      },
    },
  },
  {
    id: 'TS-KEYSTROKE-CAPTURE',
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
        const inv = invocation(path);
        if (lastSegment(inv.raw ?? inv.name) !== 'addEventListener') return;
        const event = foldString(path, inv.args[0]);
        if (event && KEY_EVENTS.has(event)) state.report('TS-KEYSTROKE-CAPTURE', path.node, event);
      },
      AssignmentExpression(path, state) {
        const n = path.node;
        if (n.type !== 'AssignmentExpression' || n.left.type !== 'MemberExpression') return;
        const prop = scopedPropertyName(path, n.left);
        if (prop === 'onkeydown' || prop === 'onkeyup' || prop === 'onkeypress' || prop === 'oninput') state.report('TS-KEYSTROKE-CAPTURE', n, prop);
      },
    },
  },
  {
    id: 'TS-CLIPBOARD',
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
        const parentType = path.parentPath?.node.type;
        if (resolvedMember(path) === 'navigator.clipboard' && (parentType === 'MemberExpression' || parentType === 'OptionalMemberExpression')) state.report('TS-CLIPBOARD', path.node);
      },
      CallExpression(path, state) {
        const inv = invocation(path);
        const name = inv.name;
        const last = lastSegment(name);
        if (last === 'addEventListener') {
          const event = foldString(path, inv.args[0]);
          if (event && CLIPBOARD_EVENTS.has(event)) state.report('TS-CLIPBOARD', path.node, `${event} listener`);
        } else if (name === 'document.execCommand') {
          const cmd = foldString(path, inv.args[0])?.toLowerCase();
          if (cmd === 'copy' || cmd === 'paste' || cmd === 'cut') state.report('TS-CLIPBOARD', path.node, `execCommand ${cmd}`);
        }
      },
    },
  },
  {
    id: 'TS-BEACON',
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
        const inv = invocation(path);
        if (inv.resolved === 'navigator.sendBeacon' || inv.resolved === 'Navigator.prototype.sendBeacon') {
          state.report('TS-BEACON', path.node);
          recordHost(state, inv.args[0]);
        }
      },
    },
  },
  {
    id: 'TS-WEBSOCKET',
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
        const inv = invocation(path);
        if (inv.resolved === 'WebSocket') {
          state.report('TS-WEBSOCKET', path.node);
          recordHost(state, inv.args[0]);
        }
      },
    },
  },
  {
    id: 'TS-REMOTE-ENDPOINT',
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
        const inv = invocation(path);
        const last = lastSegment(inv.name);
        let target: Node | undefined;
        if (inv.resolved === 'fetch') target = inv.args[0];
        else if (last === 'open' && inv.args.length >= 2) {
          const method = foldString(path, inv.args[0]);
          if (method && /^(get|post|put|patch|delete|head)$/i.test(method)) target = inv.args[1];
        }
        if (!target) return;
        const host = urlHost(stringPrefix(target));
        if (host) {
          state.report('TS-REMOTE-ENDPOINT', path.node, host);
          state.hosts.add(host);
        } else {
          // Destination computed at runtime: not reported on its own, but counts as a sink for TS-EXFIL-COMBINATION.
          state.scratch.set('dynamicSink', (state.scratch.get('dynamicSink') ?? 0) + 1);
        }
      },
      AssignmentExpression(path, state) {
        const n = path.node;
        if (n.type !== 'AssignmentExpression' || n.left.type !== 'MemberExpression' || propertyName(n.left) !== 'src') return;
        // img.src = "https://..." (tracking pixels, and pixel-based exfiltration). Script elements are TS-REMOTE-SCRIPT-LOAD.
        const kind = elementKind(path, n.left.object);
        if (kind === 'script') return;
        const host = urlHost(stringPrefix(n.right));
        if (host) {
          state.report('TS-REMOTE-ENDPOINT', n, `${kind ?? 'element'} src ${host}`);
          state.hosts.add(host);
        } else if (kind === 'img') {
          state.scratch.set('dynamicSink', (state.scratch.get('dynamicSink') ?? 0) + 1);
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
    id: 'TS-NETWORK-API-HOOK',
    name: 'Overrides network or form APIs',
    description: 'The script replaces fetch, XMLHttpRequest, WebSocket, sendBeacon, form submission or addEventListener (by assignment or Object.defineProperty).',
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
        let target: string | undefined;
        if (n.left.type === 'MemberExpression') target = resolveName(path, n.left) ?? memberChain(n.left);
        else if (n.left.type === 'Identifier' && isGlobal(path, n.left.name)) target = n.left.name;
        if (target && NETWORK_HOOK_TARGETS.has(target)) state.report('TS-NETWORK-API-HOOK', n, target);
      },
      // Object.defineProperty(window, 'fetch', …), Object.defineProperty(XMLHttpRequest.prototype, 'send', …),
      // Object.assign(window, { fetch }), Reflect.set(navigator, 'sendBeacon', …)
      CallExpression(path, state) {
        const inv = invocation(path);
        if (!inv.resolved || !PROPERTY_DEFINERS.has(inv.resolved)) return;
        for (const name of definedProperties(path, inv)) {
          if (NETWORK_HOOK_TARGETS.has(name)) state.report('TS-NETWORK-API-HOOK', path.node, `${inv.resolved} ${name}`);
        }
      },
    },
  },
  {
    id: 'TS-OBFUSCATION',
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
        const inv = invocation(path);
        const name = inv.name;
        if (inv.resolved === 'atob') state.scratch.set('atob', (state.scratch.get('atob') ?? 0) + 1);
        if (name === 'String.fromCharCode' && inv.args.length >= 8) {
          state.scratch.set('charCodes', (state.scratch.get('charCodes') ?? 0) + 1);
        }
        if (lastSegment(name) === 'unescape' || lastSegment(name) === 'decodeURIComponent') {
          if (staticString(inv.args[0])?.includes('%')) state.scratch.set('unescape', (state.scratch.get('unescape') ?? 0) + 1);
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
      if (indicators.length >= 2) state.report('TS-OBFUSCATION', ast, indicators.join('; '));
    },
  },
  {
    id: 'TS-SOURCE-REFLECTION',
    name: 'Reads its own source code',
    description: 'The script reads the source text of functions or of its own <script> element (Function.prototype.toString, fn.toString(), document.currentScript.textContent).',
    severity: 'info',
    confidence: 'medium',
    role: 'dynamic-code',
    explanation: 'Code that reads its own source can behave differently when only comments or formatting change, for example by decoding a payload hidden in a comment. A "formatting-only" change to such a script is therefore not guaranteed to be harmless.',
    investigation: 'Check what is done with the source text. Feeding it to eval/Function or decoding data from it is a strong warning sign.',
    falsePositives: 'Feature detection (checking whether a function is native via toString) and some dependency-injection and templating libraries read function source.',
    visitors: {
      MemberExpression(path, state) {
        const chain = resolvedMember(path);
        if (chain === 'Function.prototype.toString') {
          state.report('TS-SOURCE-REFLECTION', path.node, chain);
          return;
        }
        const n = path.node;
        if ((n.type === 'MemberExpression' || n.type === 'OptionalMemberExpression') && SOURCE_TEXT_PROPS.has(scopedPropertyName(path, n) ?? '')) {
          const object = resolveName(path, n.object) ?? memberChain(n.object);
          if (object === 'document.currentScript') state.report('TS-SOURCE-REFLECTION', n, `document.currentScript.${scopedPropertyName(path, n) ?? ''}`);
        }
      },
      CallExpression(path, state) {
        const inv = invocation(path);
        const callee = calleeOf(path.node);
        // fn.toString() / (function () {}).toString() / arguments.callee.toString()
        if (callee && (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression') && scopedPropertyName(path, callee) === 'toString') {
          if (isFunctionLiteralOrBinding(path, callee.object)) state.report('TS-SOURCE-REFLECTION', path.node, 'function toString()');
          return;
        }
        // String(fn)
        const arg = inv.args[0];
        if (inv.resolved === 'String' && arg && isFunctionLiteralOrBinding(path, arg)) state.report('TS-SOURCE-REFLECTION', path.node, 'String(function)');
      },
    },
  },
  {
    id: 'TS-EXFIL-COMBINATION',
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
      const sources = ['TS-SENSITIVE-FIELD-ACCESS', 'TS-KEYSTROKE-CAPTURE', 'TS-CLIPBOARD', 'TS-FORM-FIELD-ACCESS'].filter(has);
      const sinks = ['TS-BEACON', 'TS-WEBSOCKET', 'TS-REMOTE-ENDPOINT', 'TS-NETWORK-API-HOOK'].filter(has);
      const strongSource = sources.some((s) => s !== 'TS-FORM-FIELD-ACCESS');
      // fetch/XHR/image requests to a URL computed at runtime also count as a sink when a strong source is present.
      if (strongSource && (state.scratch.get('dynamicSink') ?? 0) > 0) sinks.push('request to a computed URL');
      if (sources.length > 0 && sinks.length > 0 && (strongSource || has('TS-NETWORK-API-HOOK'))) {
        state.report('TS-EXFIL-COMBINATION', ast, `sources: ${sources.join(', ')}; sinks: ${sinks.join(', ')}`);
      }
    },
  },
];

export const RULES_BY_ID: ReadonlyMap<string, Rule> = new Map(RULES.map((r) => [r.id, r]));
