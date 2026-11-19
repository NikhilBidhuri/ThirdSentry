import { readFile, stat } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { parse as parseYaml, YAMLParseError } from 'yaml';
import type { z } from 'zod';
import { ConfigError, ThirdSentryError } from '../utils/errors.js';
import { pathExists } from '../utils/fs.js';
import { ConfigSchema, ScanOptionsSchema, type BrowserProfileName, type ScanOptions, type ThirdSentryConfig } from './schema.js';
import { NetworkPolicy } from '../security/network-policy.js';
import { resolvePageUrl, validateTargetUrl } from '../security/url-validator.js';
import { storagePaths, type StoragePaths } from '../storage/paths.js';

export const CONFIG_FILE_CANDIDATES = ['thirdsentry.yml', 'thirdsentry.yaml', '.thirdsentry/config.yml', '.thirdsentry/config.yaml'];

const MAX_CONFIG_BYTES = 1024 * 1024;

export interface ResolvedPage {
  /** Page entry exactly as configured. */
  readonly configured: string;
  readonly url: string;
  /** Path + query used as a stable page key in baselines and findings. */
  readonly key: string;
  readonly sensitive: boolean;
}

export interface ResolvedSite {
  readonly name: string;
  readonly url: string;
  readonly enabled: boolean;
  readonly pages: readonly ResolvedPage[];
  readonly profile: BrowserProfileName;
  readonly scan: ScanOptions;
  readonly firstPartyDomains: readonly string[];
  readonly ignoreQueryParams: readonly string[];
}

export interface ResolvedConfig {
  readonly config: ThirdSentryConfig;
  readonly configPath: string;
  readonly baseDir: string;
  readonly paths: StoragePaths;
  readonly sites: readonly ResolvedSite[];
}

export async function findConfigFile(cwd: string, explicit?: string): Promise<string> {
  if (explicit) {
    const p = isAbsolute(explicit) ? explicit : resolve(cwd, explicit);
    if (!(await pathExists(p))) throw new ConfigError(`Config file not found: ${p}`, 'Run "thirdsentry init" to create one');
    return p;
  }
  for (const candidate of CONFIG_FILE_CANDIDATES) {
    const p = resolve(cwd, candidate);
    if (await pathExists(p)) return p;
  }
  throw new ConfigError(
    `No ThirdSentry configuration found in ${cwd}`,
    `Run "thirdsentry init" or pass --config. Looked for: ${CONFIG_FILE_CANDIDATES.join(', ')}`,
  );
}

export function formatZodIssues(error: z.ZodError): string {
  return error.issues
    .map((issue) => {
      const path = issue.path
        .map((p, i) => (typeof p === 'number' ? `[${p}]` : i === 0 ? String(p) : `.${String(p)}`))
        .join('');
      return `  - ${path || '(root)'}: ${issue.message}`;
    })
    .join('\n');
}

export function parseConfigText(text: string, source: string): ThirdSentryConfig {
  let data: unknown;
  try {
    data = parseYaml(text, { maxAliasCount: 50, prettyErrors: true });
  } catch (error) {
    if (error instanceof YAMLParseError) throw new ConfigError(`Invalid YAML in ${source}: ${error.message}`);
    // e.g. the yaml library's alias-expansion guard ("billion laughs")
    throw new ConfigError(`Could not parse ${source}: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (data === null || data === undefined) throw new ConfigError(`Config file ${source} is empty`);
  const result = ConfigSchema.safeParse(data);
  if (!result.success) {
    throw new ConfigError(`Invalid configuration in ${source}:\n${formatZodIssues(result.error)}`, 'See docs/configuration.md');
  }
  return result.data;
}

export function createNetworkPolicy(config: ThirdSentryConfig): NetworkPolicy {
  const net = config.security.network;
  return new NetworkPolicy({
    allowedPorts: net.allowedPorts,
    allowedPrivateHosts: net.allowedPrivateHosts,
    blockedHosts: net.blockedHosts,
    resolverOverrides: Object.fromEntries(Object.entries(net.resolverOverrides).map(([k, v]) => [k.toLowerCase(), v])),
  });
}

export function pageKey(url: URL): string {
  return `${url.pathname}${url.search}`;
}

function matchesSensitive(page: ResolvedPage | { key: string; configured: string }, sensitive: readonly string[]): boolean {
  return sensitive.some((s) => s === page.configured || s === page.key || (s.endsWith('*') && page.key.startsWith(s.slice(0, -1))));
}

export function resolveSites(config: ThirdSentryConfig, policy: NetworkPolicy): ResolvedSite[] {
  return config.sites.map((site, index) => {
    const where = `sites[${index}] (${site.name})`;
    let siteUrl: URL;
    try {
      siteUrl = validateTargetUrl(site.url, policy);
    } catch (error) {
      if (error instanceof ThirdSentryError) throw new ConfigError(`${where}.url: ${error.message}`, error.hint);
      throw error;
    }
    const scan = ScanOptionsSchema.parse({ ...config.defaults.scan, ...site.scan });
    const seen = new Set<string>();
    const pages: ResolvedPage[] = [];
    for (const configured of site.pages) {
      let pageUrl: URL;
      try {
        pageUrl = resolvePageUrl(siteUrl, configured, policy);
      } catch (error) {
        if (error instanceof ThirdSentryError) throw new ConfigError(`${where}.pages: ${error.message}`, error.hint);
        throw error;
      }
      pageUrl.hash = '';
      const key = pageUrl.origin === siteUrl.origin ? pageKey(pageUrl) : pageUrl.toString();
      if (seen.has(key)) continue;
      seen.add(key);
      const partial = { configured, key };
      pages.push({ configured, url: pageUrl.toString(), key, sensitive: matchesSensitive(partial, site.sensitivePages) });
    }
    return {
      name: site.name,
      url: siteUrl.toString(),
      enabled: site.enabled,
      pages,
      profile: site.browser?.profile ?? config.defaults.browser.profile,
      scan,
      firstPartyDomains: site.firstPartyDomains,
      ignoreQueryParams: site.ignoreQueryParams,
    };
  });
}

export async function loadConfig(options: { cwd?: string; configPath?: string } = {}): Promise<ResolvedConfig> {
  const cwd = options.cwd ?? process.cwd();
  const configPath = await findConfigFile(cwd, options.configPath);
  const info = await stat(configPath);
  if (info.size > MAX_CONFIG_BYTES) throw new ConfigError(`Config file ${configPath} is larger than 1 MiB`);
  const text = await readFile(configPath, 'utf8');
  const config = parseConfigText(text, configPath);
  // Config may live in .thirdsentry/config.yml; the project root is then its parent.
  let baseDir = dirname(configPath);
  if (baseDir.endsWith('.thirdsentry')) baseDir = dirname(baseDir);
  const policy = createNetworkPolicy(config);
  const sites = resolveSites(config, policy);
  return { config, configPath, baseDir, paths: storagePaths(resolve(baseDir, config.storageDir)), sites };
}

/** Filter sites by --site (comma separated names); errors on unknown names. */
export function selectSites(resolved: ResolvedConfig, siteFilter?: string): ResolvedSite[] {
  if (!siteFilter) return resolved.sites.filter((s) => s.enabled);
  const names = siteFilter.split(',').map((s) => s.trim()).filter(Boolean);
  const unknown = names.filter((n) => !resolved.sites.some((s) => s.name === n));
  if (unknown.length > 0) {
    throw new ConfigError(
      `Unknown site(s): ${unknown.join(', ')}`,
      `Configured sites: ${resolved.sites.map((s) => s.name).join(', ')}`,
    );
  }
  return resolved.sites.filter((s) => names.includes(s.name));
}
