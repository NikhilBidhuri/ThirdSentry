import type { Node } from '@babel/types';

/**
 * Small helpers for inspecting Babel AST nodes without evaluating anything.
 * All functions are pure and total: unknown shapes return undefined.
 */

const GLOBAL_PREFIXES = new Set(['window', 'self', 'globalThis', 'top', 'parent', 'frames']);

/** Static property name of a member expression, if determinable. */
export function propertyName(node: Node): string | undefined {
  if (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') return undefined;
  const prop = node.property;
  if (!node.computed && prop.type === 'Identifier') return prop.name;
  if (prop.type === 'StringLiteral') return prop.value;
  if (prop.type === 'TemplateLiteral' && prop.expressions.length === 0) return prop.quasis[0]?.value.cooked ?? undefined;
  return undefined;
}

/**
 * Dotted name of a member chain, e.g. `window.document.cookie` →
 * `document.cookie`. Global object prefixes are stripped. Returns undefined
 * for chains containing dynamic parts.
 */
export function memberChain(node: Node, maxDepth = 8): string | undefined {
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
  while (parts.length > 1 && GLOBAL_PREFIXES.has(parts[0] as string)) parts.shift();
  return parts.length ? parts.join('.') : undefined;
}

/** Minimal view of a Babel NodePath used for alias resolution (avoids a hard dependency on traverse types here). */
export interface ScopedPath {
  readonly node: Node;
  readonly scope: {
    getBinding(name: string): { readonly kind: string; readonly path: { readonly node: Node; readonly parentPath: { readonly node: Node } | null; readonly listKey?: string | null; readonly key?: string | number | null } } | undefined;
  };
}

const ALIASABLE_GLOBALS = new Set(['window', 'document', 'navigator', 'self', 'globalThis', 'localStorage', 'sessionStorage', 'location']);

/**
 * Resolve an identifier to the browser global it aliases, for the common
 * patterns `var d = document;` and `(function (w, d) { ... })(window, document)`.
 * Returns the identifier's own name when it is an unbound global.
 */
export function resolveGlobalAlias(path: ScopedPath, name: string, depth = 0): string | undefined {
  if (depth > 4) return undefined;
  const binding = path.scope.getBinding(name);
  if (!binding) return ALIASABLE_GLOBALS.has(name) ? name : undefined;
  const node = binding.path.node;
  if (binding.kind === 'param') {
    const fn = binding.path.parentPath?.node;
    if (!fn || (fn.type !== 'FunctionExpression' && fn.type !== 'ArrowFunctionExpression')) return undefined;
    const index = fn.params.indexOf(node as (typeof fn.params)[number]);
    const call = (binding.path.parentPath as unknown as { parentPath?: { node: Node } }).parentPath?.node;
    if (index < 0 || !call || call.type !== 'CallExpression' || call.callee !== fn) return undefined;
    const arg = call.arguments[index];
    if (arg?.type === 'Identifier') return ALIASABLE_GLOBALS.has(arg.name) ? arg.name : undefined;
    if (arg?.type === 'MemberExpression') {
      const chain = memberChain(arg);
      return chain && ALIASABLE_GLOBALS.has(chain) ? chain : undefined;
    }
    return undefined;
  }
  if (node.type === 'VariableDeclarator' && node.init) {
    if (node.init.type === 'Identifier') return resolveGlobalAlias(path, node.init.name, depth + 1) ?? (ALIASABLE_GLOBALS.has(node.init.name) ? node.init.name : undefined);
    if (node.init.type === 'MemberExpression') {
      const chain = memberChain(node.init);
      return chain && ALIASABLE_GLOBALS.has(chain) ? chain : undefined;
    }
  }
  return undefined;
}

/** Member chain with a leading aliased identifier replaced by the global it refers to (`d.cookie` → `document.cookie`). */
export function resolvedMemberChain(path: ScopedPath, node: Node): string | undefined {
  const chain = memberChain(node);
  if (!chain) return undefined;
  const [head, ...rest] = chain.split('.');
  if (!head || ALIASABLE_GLOBALS.has(head)) return chain;
  const alias = resolveGlobalAlias(path, head);
  if (!alias) return chain;
  const resolved = [alias, ...rest].join('.');
  return resolved.replace(/^(window|self|globalThis)\./, '');
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

/** Callee name of a call/new expression (`fetch`, `document.createElement`, ...). */
export function calleeName(node: Node): string | undefined {
  if (node.type !== 'CallExpression' && node.type !== 'NewExpression' && node.type !== 'OptionalCallExpression') return undefined;
  const callee = node.callee;
  if (callee.type === 'Identifier') return callee.name;
  if (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression') return memberChain(callee);
  // (0, eval)(...) indirect call
  if (callee.type === 'SequenceExpression') {
    const last = callee.expressions[callee.expressions.length - 1];
    if (last?.type === 'Identifier') return last.name;
  }
  return undefined;
}

/** Last segment of a dotted name. */
export function lastSegment(name: string | undefined): string | undefined {
  if (!name) return undefined;
  const i = name.lastIndexOf('.');
  return i >= 0 ? name.slice(i + 1) : name;
}

/** Static string value of a literal, template without expressions, or concatenation of such. */
export function staticString(node: Node | null | undefined, depth = 0): string | undefined {
  if (!node || depth > 20) return undefined;
  switch (node.type) {
    case 'StringLiteral':
      return node.value;
    case 'TemplateLiteral':
      if (node.expressions.length === 0) return node.quasis.map((q) => q.value.cooked ?? '').join('');
      return undefined;
    case 'BinaryExpression': {
      if (node.operator !== '+') return undefined;
      const l = staticString(node.left, depth + 1);
      const r = staticString(node.right, depth + 1);
      return l !== undefined && r !== undefined ? l + r : undefined;
    }
    default:
      return undefined;
  }
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
