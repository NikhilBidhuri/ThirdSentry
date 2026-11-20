import { describe, expect, it } from 'vitest';
import { createNetworkPolicy, parseConfigText, resolveSites } from '../../src/config/loader.js';
import { journeyHostAllowed, journeySecretNames, parseSecretRefs, substituteSecrets } from '../../src/config/journeys.js';
import { SecretRedactor } from '../../src/browser/journey-secrets.js';
import { buildWorkerEnv } from '../../src/security/worker-sandbox.js';
import { ConfigError } from '../../src/utils/errors.js';

function config(journeys: unknown[], extraSite: Record<string, unknown> = {}): string {
  return JSON.stringify({ version: 1, sites: [{ name: 'shop', url: 'https://www.shop.example/', journeys, ...extraSite }] });
}

const okSteps = [{ type: 'goto', url: '/login' }, { type: 'capture', name: 'login' }];

function parseError(journeys: unknown[]): string {
  try {
    parseConfigText(config(journeys), 'test.yml');
  } catch (error) {
    if (error instanceof ConfigError) return error.message;
    throw error;
  }
  return '';
}

describe('journey configuration', () => {
  it('accepts a journey with every step type', () => {
    const cfg = parseConfigText(
      config([
        {
          name: 'purchase',
          sensitive: true,
          timeoutMs: 60_000,
          steps: [
            { type: 'goto', url: '/login' },
            { type: 'fill', selector: '#email', value: 'qa@example.com' },
            { type: 'fill', selector: '#pw', value: '${THIRDSENTRY_SECRET_SHOP_PASSWORD}' },
            { type: 'select', selector: '#country', value: 'DE' },
            { type: 'check', selector: '#terms' },
            { type: 'click', selector: '#login' },
            { type: 'press', key: 'Tab' },
            { type: 'waitFor', url: '**/account' },
            { type: 'waitFor', selector: '#cart' },
            { type: 'waitFor', loadState: 'networkidle' },
            { type: 'capture', name: 'account', sensitive: false },
          ],
        },
      ]),
      'test.yml',
    );
    expect(cfg.sites[0]?.journeys[0]?.steps).toHaveLength(11);
    expect(cfg.sites[0]?.journeys[0]?.steps[5]).toMatchObject({ type: 'click', allowSubmit: false });
  });

  it('defaults to no journeys', () => {
    expect(parseConfigText(JSON.stringify({ sites: [{ name: 'a', url: 'https://a.example/' }] }), 'x').sites[0]?.journeys).toEqual([]);
  });

  it('rejects environment variables other than THIRDSENTRY_SECRET_*', () => {
    for (const value of ['${HOME}', '${GITHUB_TOKEN}', '${THIRDSENTRY_SLACK_WEBHOOK}', '${thirdsentry_secret_x}', '${THIRDSENTRY_SECRET_}', 'x${THIRDSENTRY_SECRET_A', '${}']) {
      const message = parseError([{ name: 'j', steps: [{ type: 'fill', selector: '#a', value }, ...okSteps] }]);
      expect(message, value).toContain('fill values may only reference');
    }
  });

  it('allows several secret references and literal dollar signs in a fill value', () => {
    expect(parseError([{ name: 'j', steps: [{ type: 'fill', selector: '#a', value: '${THIRDSENTRY_SECRET_A}:${THIRDSENTRY_SECRET_B} costs $5' }, ...okSteps] }])).toBe('');
  });

  it('rejects secret references anywhere but the value of a fill step', () => {
    for (const step of [
      { type: 'goto', url: '/x?p=${THIRDSENTRY_SECRET_A}' },
      { type: 'click', selector: '#${THIRDSENTRY_SECRET_A}' },
      { type: 'select', selector: '#a', value: '${THIRDSENTRY_SECRET_A}' },
      { type: 'fill', selector: '#${THIRDSENTRY_SECRET_A}', value: 'x' },
      { type: 'waitFor', url: '**/${THIRDSENTRY_SECRET_A}' },
    ]) {
      expect(parseError([{ name: 'j', steps: [step, ...okSteps] }]), JSON.stringify(step)).toContain('only the "value" of a "fill" step');
    }
  });

  it('rejects unknown step types, unknown keys and malformed steps', () => {
    expect(parseError([{ name: 'j', steps: [{ type: 'evaluate', code: 'alert(1)' }, ...okSteps] }])).toContain('steps[0]');
    expect(parseError([{ name: 'j', steps: [{ type: 'click', selector: '#a', force: true }, ...okSteps] }])).toContain('force');
    expect(parseError([{ name: 'j', steps: [{ type: 'waitFor' }, ...okSteps] }])).toContain('exactly one');
    expect(parseError([{ name: 'j', steps: [{ type: 'waitFor', selector: '#a', url: '**/x' }, ...okSteps] }])).toContain('exactly one');
    expect(parseError([{ name: 'j', steps: [{ type: 'press', key: 'Enter;rm' }, ...okSteps] }])).toContain('key name');
    expect(parseError([{ name: 'j', allowSubmit: true, steps: okSteps }])).toContain('allowSubmit');
  });

  it('requires a capture, unique capture names, unique journey names and a step limit', () => {
    expect(parseError([{ name: 'j', steps: [{ type: 'goto', url: '/a' }] }])).toContain('at least one "capture"');
    expect(parseError([{ name: 'j', steps: [...okSteps, ...okSteps] }])).toContain('duplicate capture name');
    expect(parseError([{ name: 'j', steps: okSteps }, { name: 'j', steps: okSteps }])).toContain('duplicate journey name');
    expect(parseError([{ name: 'j', steps: Array.from({ length: 101 }, () => ({ type: 'goto', url: '/a' })) }])).toBeTruthy();
    expect(parseError([{ name: 'bad/name', steps: okSteps }])).toContain('journeys[0].name');
  });

  it('resolves captures as stable page keys after the plain pages, with sensitivity inheritance', () => {
    const cfg = parseConfigText(
      config([{ name: 'buy', sensitive: true, storageState: 'sessions/a.json', steps: [{ type: 'goto', url: '/cart' }, { type: 'capture', name: 'cart' }, { type: 'capture', name: 'pub', sensitive: false }] }], { pages: ['/', '/about'] }),
      'x',
    );
    const [site] = resolveSites(cfg, createNetworkPolicy(cfg), '/base');
    expect(site?.pages.map((p) => p.key)).toEqual(['/', '/about', 'journey:buy/cart', 'journey:buy/pub']);
    expect(site?.pages.map((p) => p.sensitive)).toEqual([false, false, true, false]);
    const journey = site?.journeys?.[0];
    expect(journey?.steps[0]).toMatchObject({ type: 'goto', url: 'https://www.shop.example/cart' });
    expect(journey?.storageState).toMatch(/sessions[\\/]a\.json$/);
  });

  it('restricts goto to the site registrable domain plus allowedHosts', () => {
    const make = (url: string, allowedHosts: string[] = []): string => config([{ name: 'j', allowedHosts, steps: [{ type: 'goto', url }, { type: 'capture', name: 'c' }] }]);
    const resolve = (text: string): unknown => {
      const cfg = parseConfigText(text, 'x');
      return resolveSites(cfg, createNetworkPolicy(cfg));
    };
    expect(() => resolve(make('https://evil.example.org/'))).toThrow(/outside the site's registrable domain/);
    expect(() => resolve(make('https://shop.example.evil.com/'))).toThrow(ConfigError);
    expect(() => resolve(make('//evil.example/x'))).toThrow();
    expect(() => resolve(make('javascript:alert(1)'))).toThrow();
    expect(() => resolve(make('https://checkout.shop.example/pay'))).not.toThrow();
    expect(() => resolve(make('https://pay.partner.example/', ['pay.partner.example']))).not.toThrow();
  });

  it('host matching', () => {
    expect(journeyHostAllowed('a.shop.example', 'www.shop.example', [])).toBe(true);
    expect(journeyHostAllowed('shop.example', 'www.shop.example', [])).toBe(true);
    expect(journeyHostAllowed('other.example', 'www.shop.example', [])).toBe(false);
    expect(journeyHostAllowed('x.partner.example', 'www.shop.example', ['*.partner.example'])).toBe(true);
    expect(journeyHostAllowed('localhost', 'localhost', [])).toBe(true);
  });
});

describe('journey secrets', () => {
  it('parses and substitutes references', () => {
    expect(parseSecretRefs('a${THIRDSENTRY_SECRET_X}b${THIRDSENTRY_SECRET_Y}').names).toEqual(['THIRDSENTRY_SECRET_X', 'THIRDSENTRY_SECRET_Y']);
    const r = substituteSecrets('u:${THIRDSENTRY_SECRET_X}', { THIRDSENTRY_SECRET_X: 'hunter2hunter2' });
    expect(r).toMatchObject({ value: 'u:hunter2hunter2', secrets: ['hunter2hunter2'], missing: [] });
    expect(substituteSecrets('${THIRDSENTRY_SECRET_X}', {}).missing).toEqual(['THIRDSENTRY_SECRET_X']);
    // never expands anything else
    expect(substituteSecrets('${HOME}', { HOME: '/root' }).value).toBe('${HOME}');
  });

  it('collects only referenced secret names from sites', () => {
    const cfg = parseConfigText(
      config([{ name: 'j', steps: [{ type: 'fill', selector: '#a', value: '${THIRDSENTRY_SECRET_B}' }, { type: 'fill', selector: '#c', value: '${THIRDSENTRY_SECRET_A}' }, ...okSteps] }]),
      'x',
    );
    expect(journeySecretNames(resolveSites(cfg, createNetworkPolicy(cfg)))).toEqual(['THIRDSENTRY_SECRET_A', 'THIRDSENTRY_SECRET_B']);
  });

  it('passes only the referenced secrets (never alert credentials) into the worker environment', () => {
    const parent: NodeJS.ProcessEnv = {
      PATH: '/bin',
      THIRDSENTRY_SECRET_SHOP: 'pw-one-pw-one',
      THIRDSENTRY_SECRET_OTHER: 'not-referenced',
      THIRDSENTRY_SLACK_WEBHOOK: 'https://hooks.example/x',
      GITHUB_TOKEN: 'ghp_x',
    };
    const env = buildWorkerEnv('/tmp/sandbox', parent, 'info', ['THIRDSENTRY_SECRET_SHOP', 'GITHUB_TOKEN', 'THIRDSENTRY_SLACK_WEBHOOK']);
    expect(env.THIRDSENTRY_SECRET_SHOP).toBe('pw-one-pw-one');
    expect(env.THIRDSENTRY_SECRET_OTHER).toBeUndefined();
    expect(env.GITHUB_TOKEN).toBeUndefined();
    expect(env.THIRDSENTRY_SLACK_WEBHOOK).toBeUndefined();
    expect(buildWorkerEnv('/tmp/sandbox', parent).THIRDSENTRY_SECRET_SHOP).toBeUndefined();
  });

  it('redacts raw, URL-encoded and base64 forms deeply but leaves opaque bodies alone', () => {
    const secret = 'p@ss w0rd/value';
    const r = new SecretRedactor();
    r.add(secret);
    const out = r.deep({
      url: `https://x.example/?p=${encodeURIComponent(secret)}`,
      list: [`typed ${secret}`, { [`k ${secret}`]: 'v' }],
      auth: Buffer.from(secret).toString('base64'),
      bodyBase64: Buffer.from(secret).toString('base64'),
      n: 3,
    });
    const text = JSON.stringify(out);
    expect(text).not.toContain(secret);
    expect(text).not.toContain(encodeURIComponent(secret));
    expect(out.bodyBase64).toBe(Buffer.from(secret).toString('base64'));
    expect(out.auth).toBe('[REDACTED]');
    expect(out.n).toBe(3);
    expect(r.hits).toBeGreaterThan(0);
  });
});
