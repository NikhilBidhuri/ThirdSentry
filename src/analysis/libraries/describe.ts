import { compareVersions } from './version.js';

const DISPLAY: Record<string, string> = {
  jquery: 'jQuery',
  'jquery-ui': 'jQuery UI',
  bootstrap: 'Bootstrap',
  lodash: 'Lodash',
  moment: 'Moment.js',
  angularjs: 'AngularJS',
  handlebars: 'Handlebars',
  dompurify: 'DOMPurify',
  underscore: 'Underscore.js',
};

export function libraryDisplayName(name: string): string {
  return DISPLAY[name] ?? name;
}

export function libraryLabel(l: { readonly name: string; readonly version: string }): string {
  return `${libraryDisplayName(l.name)} ${l.version}`;
}

/** "jQuery 3.5.1 → 3.7.1" for libraries whose version differs between the approved and the current resource. */
export function describeLibraryChange(
  previous: ReadonlyArray<{ readonly name: string; readonly version: string }> | undefined,
  current: ReadonlyArray<{ readonly name: string; readonly version: string }> | undefined,
): { readonly text: string; readonly downgrade: boolean } | undefined {
  if (!previous?.length || !current?.length) return undefined;
  const parts: string[] = [];
  let downgrade = false;
  for (const c of current) {
    const before = previous.filter((p) => p.name === c.name).map((p) => p.version);
    if (before.length === 0 || before.includes(c.version)) continue;
    const from = before[0] as string;
    if ((compareVersions(c.version, from) ?? 0) < 0) downgrade = true;
    parts.push(`${libraryDisplayName(c.name)} ${from} → ${c.version}`);
  }
  return parts.length ? { text: parts.join(', '), downgrade } : undefined;
}
