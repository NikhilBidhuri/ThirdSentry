import type { NodePath } from '@babel/traverse';
import type { Node } from '@babel/types';

/**
 * Small helpers for inspecting Babel AST nodes without evaluating anything.
 * All functions are pure and total: unknown shapes return undefined.
 *
 * Name resolution is deliberately conservative in one direction only: when
 * code *might* refer to a sensitive global (through a constant-folded
 * computed name such as `window['ev' + 'al']`, or a simple alias such as
 * `var e = eval`), it is resolved to that global, so evasions are flagged.
 */

const GLOBAL_PREFIXES = new Set(['window', 'self', 'globalThis', 'top', 'parent', 'frames']);
const MAX_DEPTH = 8;

/** A Babel NodePath (scope-aware). Kept as a named alias for existing call sites. */
export type ScopedPath = NodePath;

type Binding = NonNullable<ReturnType<NodePath['scope']['getBinding']>>;

function stripGlobalPrefixes(parts: string[]): string[] {
  while (parts.length > 1 && GLOBAL_PREFIXES.has(parts[0] as string)) parts.shift();
  return parts;
}

/** Static property name of a member expression, if determinable (constant-folded for computed names). */
export function propertyName(node: Node): string | undefined {
  if (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') return undefined;
  const prop = node.property;
  if (!node.computed && prop.type === 'Identifier') return prop.name;
  if (prop.type === 'PrivateName') return undefined;
  return staticString(prop);
}

/**
 * Dotted name of a member chain, e.g. `window.document.cookie` →
 * `document.cookie`. Global object prefixes are stripped. Returns undefined
 * for chains containing dynamic parts.
 */
export function memberChain(node: Node, maxDepth = MAX_DEPTH): string | undefined {
  const parts: string[] = [];
  let current: Node = node;
  for (let i = 0; i < maxDepth; i++) {
    if (current.type === 'Identifier') {
      parts.unshift(current.name);
      break;
    }
    if (current.type === 'ThisExpression') {
      parts.unshift('this');
      break;
    }
    if (current.type === 'MemberExpression' || current.type === 'OptionalMemberExpression') {
      const name = propertyName(current);
      if (name === undefined) return undefined;
      parts.unshift(name);
      current = current.object;
      continue;
    }
    if (current.type === 'CallExpression' && current.callee.type === 'Identifier' && parts.length > 0) {
      // e.g. document.getElementById(...).value  →  "getElementById().value"
      parts.unshift(`${current.callee.name}()`);
      break;
    }
    return undefined;
  }
  stripGlobalPrefixes(parts);
  return parts.length ? parts.join('.') : undefined;
}

/** Initial value of a binding: the declarator's init, or the single value assigned to an uninitialised variable. */
function bindingValue(binding: Binding): { node: Node; path: NodePath } | undefined {
  const node = binding.path.node;
  if (node.type === 'VariableDeclarator') {
    if (node.init) return { node: node.init, path: binding.path };
    const [only, ...more] = binding.constantViolations;
    if (only && more.length === 0 && only.node.type === 'AssignmentExpression' && only.node.operator === '=') {
      return { node: only.node.right, path: only };
    }
  }
  return undefined;
}

/** Argument passed for an IIFE parameter, e.g. `(function (w) { … })(window)` → `window`. */
function iifeArgument(binding: Binding): { node: Node; path: NodePath } | undefined {
  const fnPath = binding.path.parentPath;
  const fn = fnPath?.node;
  if (!fnPath || !fn || (fn.type !== 'FunctionExpression' && fn.type !== 'ArrowFunctionExpression')) return undefined;
  const index = fn.params.indexOf(binding.path.node as (typeof fn.params)[number]);
  const callPath = fnPath.parentPath;
  const call = callPath?.node;
  if (index < 0 || !callPath || !call || call.type !== 'CallExpression' || call.callee !== fn) return undefined;
  const arg = call.arguments[index];
  if (!arg || arg.type === 'SpreadElement' || arg.type === 'ArgumentPlaceholder') return undefined;
  return { node: arg, path: callPath };
}

/**
 * Constant-fold a string-valued expression: string/number literals,
 * template literals whose expressions fold, `+` concatenation, and (with a
 * scope) identifiers bound to such a value, e.g. `const k = 'coo' + 'kie'`.
 */
export function foldString(path: NodePath | undefined, node: Node | null | undefined, depth = 0): string | undefined {
  if (!node || depth > 20) return undefined;
  switch (node.type) {
    case 'StringLiteral':
      return node.value;
    case 'NumericLiteral':
      return depth > 0 ? String(node.value) : undefined;
    case 'TemplateLiteral': {
      let out = node.quasis[0]?.value.cooked ?? '';
      for (let i = 0; i < node.expressions.length; i++) {
        const part = foldString(path, node.expressions[i], depth + 1);
        if (part === undefined) return undefined;
        out += part + (node.quasis[i + 1]?.value.cooked ?? '');
      }
      return out;
    }
    case 'BinaryExpression': {
      if (node.operator !== '+') return undefined;
      const l = foldString(path, node.left, depth + 1);
      const r = l === undefined ? undefined : foldString(path, node.right, depth + 1);
      return l !== undefined && r !== undefined ? l + r : undefined;
    }
    case 'Identifier': {
      if (!path) return undefined;
      const binding = path.scope.getBinding(node.name);
      if (!binding || (binding.kind !== 'const' && binding.kind !== 'var' && binding.kind !== 'let')) return undefined;
      if (binding.kind !== 'const' && binding.constantViolations.length > 0) return undefined;
      const value = bindingValue(binding);
      return value ? foldString(value.path, value.node, depth + 5) : undefined;
    }
    default:
      return undefined;
  }
}

/** Property name of a member expression, resolving constant-bound computed keys (`obj[k]` with `const k = 'cookie'`). */
export function scopedPropertyName(path: NodePath, node: Node): string | undefined {
  if (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') return undefined;
  return propertyName(node) ?? (node.computed ? foldString(path, node.property) : undefined);
}

/**
 * Resolve an expression to the dotted name of the global it refers to:
 * `window['ev' + 'al']` → `eval`, `var e = eval; e` → `eval`,
 * `var p = XMLHttpRequest.prototype; p.open` → `XMLHttpRequest.prototype.open`,
 * `(function (d) { d.cookie })(document)` → `document.cookie`,
 * `navigator.sendBeacon.bind(navigator)` → `navigator.sendBeacon`.
 * Returns undefined when the expression is (or starts at) a local value
 * that cannot be traced to a global.
 */
export function resolveName(path: NodePath, node: Node, depth = 0): string | undefined {
  if (depth > MAX_DEPTH) return undefined;
  switch (node.type) {
    case 'Identifier': {
      const binding = path.scope.getBinding(node.name);
      if (!binding) return node.name;
      const value = binding.kind === 'param' ? iifeArgument(binding) : bindingValue(binding);
      return value ? resolveName(value.path, value.node, depth + 1) : undefined;
    }
    case 'MemberExpression':
    case 'OptionalMemberExpression': {
      const prop = scopedPropertyName(path, node);
      if (prop === undefined) return undefined;
      const object = resolveName(path, node.object, depth + 1);
      if (object === undefined) return undefined;
      return stripGlobalPrefixes([...object.split('.'), prop]).join('.');
    }
    case 'CallExpression':
    case 'OptionalCallExpression': {
      // f.bind(thisArg) returns (a bound copy of) f.
      const callee = node.callee;
      if ((callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression') && propertyName(callee) === 'bind') {
        return resolveName(path, callee.object, depth + 1);
      }
      return undefined;
    }
    case 'SequenceExpression': {
      const last = node.expressions[node.expressions.length - 1];
      return last ? resolveName(path, last, depth + 1) : undefined;
    }
    case 'LogicalExpression':
      return resolveName(path, node.left, depth + 1);
    default:
      return undefined;
  }
}

/** Member chain resolved through aliases and computed names, falling back to the literal chain (`d.cookie` → `document.cookie`). */
export function resolvedMemberChain(path: ScopedPath, node: Node): string | undefined {
  return resolveName(path, node) ?? memberChain(node);
}

/** Callee of a call, optional call, `new` or tagged template expression. */
export function calleeOf(node: Node): Node | undefined {
  if (node.type === 'CallExpression' || node.type === 'NewExpression' || node.type === 'OptionalCallExpression') return node.callee;
  if (node.type === 'TaggedTemplateExpression') return node.tag;
  return undefined;
}

/**
 * Arguments of an invocation. For a tagged template the template literal
 * stands in for the first argument: `Function\`code\`` and
 * `setTimeout\`code\`` receive the template strings, which are converted to
 * code exactly like a string argument.
 */
export function callArguments(node: Node): Node[] {
  if (node.type === 'CallExpression' || node.type === 'NewExpression' || node.type === 'OptionalCallExpression') {
    return node.arguments.filter((a) => a.type !== 'SpreadElement' && a.type !== 'ArgumentPlaceholder');
  }
  if (node.type === 'TaggedTemplateExpression') return [node.quasi];
  return [];
}

/**
 * Kind of element an expression refers to, when statically evident:
 * `document.createElement('script')`, `new Image()`, or a variable initialised with one of those.
 */
export function elementKind(path: ScopedPath, node: Node, depth = 0): string | undefined {
  if (depth > 3) return undefined;
  if (node.type === 'NewExpression' && node.callee.type === 'Identifier' && node.callee.name === 'Image') return 'img';
  if (node.type === 'CallExpression') {
    const name = lastSegment(calleeName(node));
    if (name === 'createElement') {
      const arg = node.arguments[0];
      const tag = arg && arg.type !== 'SpreadElement' && arg.type !== 'ArgumentPlaceholder' ? staticString(arg) : undefined;
      return tag?.toLowerCase();
    }
    return undefined;
  }
  if (node.type === 'Identifier') {
    const binding = path.scope.getBinding(node.name);
    const decl = binding?.path.node;
    if (decl?.type === 'VariableDeclarator' && decl.init) return elementKind(path, decl.init, depth + 1);
  }
  return undefined;
}

/** Callee name of a call/new/tagged-template expression (`fetch`, `document.createElement`, ...), without alias resolution. */
export function calleeName(node: Node): string | undefined {
  const callee = calleeOf(node);
  if (!callee) return undefined;
  if (callee.type === 'Identifier') return callee.name;
  if (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression') return memberChain(callee);
  // (0, eval)(...) indirect call
  if (callee.type === 'SequenceExpression') {
    const last = callee.expressions[callee.expressions.length - 1];
    if (last?.type === 'Identifier') return last.name;
    if (last?.type === 'MemberExpression') return memberChain(last);
  }
  return undefined;
}

/** Last segment of a dotted name. */
export function lastSegment(name: string | undefined): string | undefined {
  if (!name) return undefined;
  const i = name.lastIndexOf('.');
  return i >= 0 ? name.slice(i + 1) : name;
}

/** Static string value of a literal, template (with foldable expressions) or concatenation of such. */
export function staticString(node: Node | null | undefined): string | undefined {
  return foldString(undefined, node);
}

/**
 * Best-effort prefix of a string-producing expression: for
 * `"https://x.example/c?d=" + data` returns `https://x.example/c?d=`.
 */
export function stringPrefix(node: Node | null | undefined, depth = 0): string | undefined {
  if (!node || depth > 20) return undefined;
  const full = staticString(node);
  if (full !== undefined) return full;
  if (node.type === 'TemplateLiteral') return node.quasis[0]?.value.cooked ?? undefined;
  if (node.type === 'BinaryExpression' && node.operator === '+') return stringPrefix(node.left, depth + 1);
  return undefined;
}

/** True when the expression is string-like (literal, template or concatenation involving one). */
export function isStringish(node: Node | null | undefined, depth = 0): boolean {
  if (!node || depth > 20) return false;
  if (node.type === 'StringLiteral' || node.type === 'TemplateLiteral') return true;
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return isStringish(node.left, depth + 1) || isStringish(node.right, depth + 1);
  }
  return false;
}

/** Extract the hostname of an absolute http(s)/ws(s) URL, or of a protocol-relative URL. */
export function urlHost(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const m = /^(?:(?:https?|wss?):)?\/\/([a-z0-9.-]+\.[a-z]{2,63}|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:[/?#]|$)/i.exec(value.trim());
  return m?.[1]?.toLowerCase();
}

/** Shannon entropy in bits per character. */
export function entropy(value: string): number {
  if (!value) return 0;
  const freq = new Map<string, number>();
  for (const ch of value) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / value.length;
    h -= p * Math.log2(p);
  }
  return h;
}
