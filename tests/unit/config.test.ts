import { describe, expect, it } from 'vitest';
import { createNetworkPolicy, parseConfigText, resolveSites } from '../../src/config/loader.js';
import { ConfigError } from '../../src/utils/errors.js';
import { CONFIG_TEMPLATE } from '../../src/config/defaults.js';

const minimal = `
sites:
  - name: store
    url: https://example.com
    pages: ['/', '/checkout']
    sensitivePages: ['/checkout']
`;

describe('configuration', () => {
  it('applies defaults', () => {
    const cfg = parseConfigText(minimal, 'test.yml');
    expect(cfg.version).toBe(1);
    expect(cfg.storageDir).toBe('.thirdsentry');
    expect(cfg.defaults.browser.profile).toBe('desktop-chromium');
    expect(cfg.defaults.scan.waitUntil).toBe('networkidle');
    expect(cfg.limits.maxResourceBytes).toBe(5 * 1024 * 1024);
    expect(cfg.security.network.allowedPorts).toEqual([80, 443]);
    expect(cfg.security.isolation.mode).toBe('process');
    expect(cfg.serviceWorkers.strategy).toBe('block');
    expect(cfg.retention.storeScriptContent).toBe(false);
  });

  it('resolves pages, sensitivity and per-site overrides', () => {
    const cfg = parseConfigText(
      `${minimal}    browser: { profile: mobile-webkit }\n    scan: { timeout: 5000 }\n`,
      'test.yml',
    );
    const [site] = resolveSites(cfg, createNetworkPolicy(cfg));
    expect(site?.profile).toBe('mobile-webkit');
    expect(site?.scan.timeout).toBe(5000);
    expect(site?.scan.waitUntil).toBe('networkidle');
    expect(site?.pages.map((p) => [p.key, p.sensitive])).toEqual([
      ['/', false],
      ['/checkout', true],
    ]);
  });

  it('rejects unknown keys (typos)', () => {
    expect(() => parseConfigText(`${minimal}    enable: false\n`, 'test.yml')).toThrow(/enable|Unrecognized/i);
  });

  it('rejects duplicate site names', () => {
    const text = `sites:\n  - { name: a, url: 'https://a.example' }\n  - { name: a, url: 'https://b.example' }\n`;
    expect(() => parseConfigText(text, 'x.yml')).toThrow(/duplicate site name/);
  });

  it('rejects invalid profiles and site names with a readable path', () => {
    try {
      parseConfigText(`sites:\n  - { name: 'bad name', url: 'https://a.example', browser: { profile: ie6 } }\n`, 'x.yml');
      expect.fail('should throw');
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigError);
      expect((error as Error).message).toMatch(/sites\[0\]\.name/);
      expect((error as Error).message).toMatch(/sites\[0\]\.browser\.profile/);
    }
  });

  it('rejects invalid YAML and empty files', () => {
    expect(() => parseConfigText('sites: [', 'x.yml')).toThrow(ConfigError);
    expect(() => parseConfigText('', 'x.yml')).toThrow(/empty/);
  });

  it('rejects sites pointing at internal addresses', () => {
    const cfg = parseConfigText(`sites:\n  - { name: a, url: 'http://169.254.169.254/' }\n`, 'x.yml');
    expect(() => resolveSites(cfg, createNetworkPolicy(cfg))).toThrow(/sites\[0\]/);
  });

  it('accepts the init template', () => {
    const text = CONFIG_TEMPLATE.replace('__SITE_NAME__', 'my-site').replace('__SITE_URL__', 'https://example.com');
    const cfg = parseConfigText(text, 'template.yml');
    expect(cfg.sites[0]?.name).toBe('my-site');
  });

  it('limits YAML alias expansion (billion laughs)', () => {
    const bomb = `a: &a ["x","x","x","x","x","x","x","x","x"]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\ne: [*d,*d,*d,*d,*d,*d,*d,*d,*d]\nsites: []\n`;
    expect(() => parseConfigText(bomb, 'bomb.yml')).toThrow(ConfigError);
  });
});
