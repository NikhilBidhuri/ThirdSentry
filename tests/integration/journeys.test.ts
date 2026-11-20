import type * as NodeFs from 'node:fs';
import { createRequire } from 'node:module';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { FixtureServer } from '../fixtures/server.js';
import { installJourneySite, JOURNEY_PASSWORD, SESSION_COOKIE, type JourneySiteState } from '../fixtures/journey-site.js';
import { makeProject } from '../helpers.js';
import { selectSites, type ResolvedConfig } from '../../src/config/loader.js';
import { buildCollectRequest, persistScan } from '../../src/monitoring/scan-manager.js';
import { collectEvidence } from '../../src/browser/collector.js';
import { analyzeScan } from '../../src/monitoring/analysis-runner.js';
import { configureLogger } from '../../src/utils/logger.js';
import type { PageEvidence, ScanEvidence } from '../../src/types/evidence.js';

const server = new FixtureServer();
let state: JourneySiteState;
const SECRET_VAR = 'THIRDSENTRY_SECRET_SHOP_PASSWORD';

beforeAll(async () => {
  await server.start();
  state = installJourneySite(server);
});
afterAll(async () => {
  await server.stop();
});
afterEach(() => {
  delete process.env[SECRET_VAR];
  state.loginBodies.length = 0;
  state.payPosts.length = 0;
});

const loginSteps = [
  { type: 'goto', url: '/login' },
  { type: 'fill', selector: '#user', value: 'tester' },
  { type: 'fill', selector: '#pass', value: '${' + SECRET_VAR + '}' },
  { type: 'click', selector: '#login' },
  { type: 'waitFor', url: '**/account', timeoutMs: 4000 },
];

function site(journeys: unknown[], extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { name: 'shop', url: `http://shop.test:${server.port}/`, pages: ['/'], journeys, ...extra };
}

async function run(
  journeys: unknown[],
  options: { siteExtra?: Record<string, unknown>; scan?: Record<string, unknown> } = {},
): Promise<{ evidence: ScanEvidence; resolved: ResolvedConfig; dir: string; cleanup: () => Promise<void> }> {
  const project = await makeProject(server.port, {
    sites: [site(journeys, options.siteExtra)],
    ...(options.scan ? { defaults: { scan: { timeout: 15_000, waitUntil: 'networkidle', networkIdleTimeout: 3_000, settleMs: 300, ...options.scan } } } : {}),
  });
  const request = buildCollectRequest(project.resolved, selectSites(project.resolved));
  const evidence = await collectEvidence(request);
  return { evidence, resolved: project.resolved, dir: project.dir, cleanup: project.cleanup };
}

function pageOf(evidence: ScanEvidence, key: string): PageEvidence {
  const p = evidence.sites[0]?.pages.find((x) => x.pageKey === key);
  if (!p) throw new Error(`no page ${key}`);
  return p;
}

function scriptUrls(p: PageEvidence): string[] {
  return [...p.scriptResponses.map((s) => s.url), ...p.domScripts.flatMap((s) => (s.src ? [s.src] : []))];
}

const purchase = {
  name: 'purchase',
  sensitive: true,
  steps: [
    ...loginSteps,
    { type: 'capture', name: 'account' },
    { type: 'goto', url: '/cart' },
    { type: 'capture', name: 'cart' },
    { type: 'click', selector: '#to-checkout' },
    { type: 'waitFor', url: '**/checkout', timeoutMs: 4000 },
    { type: 'capture', name: 'checkout' },
  ],
};

describe('logged-in journeys (local fixture site)', () => {
  it('logs in, walks cart and checkout, and captures the script only visible when logged in', async () => {
    process.env[SECRET_VAR] = JOURNEY_PASSWORD;
    const { evidence, resolved, cleanup } = await run([purchase]);
    try {
      const keys = evidence.sites[0]?.pages.map((p) => p.pageKey);
      expect(keys).toEqual(['/', 'journey:purchase/account', 'journey:purchase/cart', 'journey:purchase/checkout']);
      for (const p of evidence.sites[0]?.pages ?? []) expect(p.status, p.pageKey).toBe('complete');

      // The browser really typed the secret: the server received it.
      expect(state.loginBodies.join('')).toContain(`pass=${JOURNEY_PASSWORD}`);

      const checkout = pageOf(evidence, 'journey:purchase/checkout');
      expect(checkout.sensitive).toBe(true);
      expect(checkout.finalUrl).toMatch(/\/checkout$/);
      expect(scriptUrls(checkout).some((u) => u.endsWith('/pay-loggedin.js'))).toBe(true);
      // Evidence per capture covers its own segment: the checkout script is not on earlier captures or the plain page.
      expect(scriptUrls(pageOf(evidence, 'journey:purchase/cart')).some((u) => u.endsWith('/pay-loggedin.js'))).toBe(false);
      expect(scriptUrls(pageOf(evidence, '/')).some((u) => u.endsWith('/pay-loggedin.js'))).toBe(false);
      expect(scriptUrls(pageOf(evidence, 'journey:purchase/cart')).some((u) => u.endsWith('/cart-widget.js'))).toBe(true);
      expect(scriptUrls(pageOf(evidence, 'journey:purchase/account')).some((u) => u.endsWith('/cart-widget.js'))).toBe(false);
      expect(pageOf(evidence, 'journey:purchase/account').domScripts.some((s) => s.kind === 'inline' && s.text?.includes('accountPage'))).toBe(true);

      // Baselines, comparison and reports work unchanged: process the evidence like a normal scan.
      const run = await persistScan(resolved, evidence);
      const resource = run.result.sites[0]?.resources.find((r) => r.finalUrl?.endsWith('/pay-loggedin.js'));
      expect(resource?.pages).toEqual(['journey:purchase/checkout']);
      const { report } = await analyzeScan(resolved, run.result, { scanPath: run.scanPath, updateState: false });
      expect(JSON.stringify(report)).not.toContain(JOURNEY_PASSWORD);
      expect(JSON.stringify(run.result)).not.toContain(JOURNEY_PASSWORD);
    } finally {
      await cleanup();
    }
  }, 120_000);

  it('never leaks the typed secret into evidence, logs or reports (even when the page echoes it)', async () => {
    process.env[SECRET_VAR] = JOURNEY_PASSWORD;
    // A page that reflects the secret in its URL and console would otherwise leak it.
    server.set('shop.test', '/echo', {
      handler: (_req, res) => {
        res.writeHead(200, { 'content-type': 'text/html' }).end(`<!doctype html><script>console.error('pw ${JOURNEY_PASSWORD}'); history.replaceState(null, '', '/echo?p=${JOURNEY_PASSWORD}');</script>`);
      },
    });
    const written: string[] = [];
    // The logger writes to fd 2 through the CommonJS fs object.
    const nodeFs = createRequire(import.meta.url)('node:fs') as typeof NodeFs;
    const realWrite = nodeFs.writeSync.bind(nodeFs) as unknown as (...a: unknown[]) => number;
    const spy = vi.spyOn(nodeFs, 'writeSync').mockImplementation(((fd: number, data: unknown, ...rest: unknown[]) => {
      if (fd === 2) written.push(String(data));
      return realWrite(fd, data, ...rest);
    }));
    configureLogger({ level: 'debug' });
    const journey = {
      name: 'echo',
      steps: [...loginSteps, { type: 'goto', url: '/echo' }, { type: 'capture', name: 'echo' }, { type: 'fill', selector: '#missing', value: '${' + SECRET_VAR + '}', timeoutMs: 600 }, { type: 'capture', name: 'never' }],
    };
    const { evidence, resolved, cleanup } = await run([journey], { scan: { captureScreenshots: true } });
    spy.mockRestore();
    configureLogger({ level: 'info' });
    try {
      const echo = pageOf(evidence, 'journey:echo/echo');
      expect(echo.status).toBe('complete');
      expect(echo.screenshotBase64).toBeTruthy();
      const never = pageOf(evidence, 'journey:echo/never');
      expect(never.status).toBe('failed');
      const everything = JSON.stringify(evidence);
      expect(everything).not.toContain(JOURNEY_PASSWORD);
      expect(everything).not.toContain(encodeURIComponent(JOURNEY_PASSWORD));
      expect(everything).toContain('[REDACTED]');
      expect(echo.issues.some((i) => i.code === 'secret-redacted')).toBe(true);
      expect(written.join('')).toContain('journey step failed'); // the spy sees the logger output
      expect(written.join('')).not.toContain(JOURNEY_PASSWORD);
      const run2 = await persistScan(resolved, evidence);
      const { report } = await analyzeScan(resolved, run2.result, { scanPath: run2.scanPath, updateState: false });
      expect(JSON.stringify(run2.result) + JSON.stringify(report)).not.toContain(JOURNEY_PASSWORD);
    } finally {
      await cleanup();
    }
  }, 120_000);

  it('marks the failing capture failed, later ones not reached, and keeps scanning other pages', async () => {
    process.env[SECRET_VAR] = 'wrong-password-123';
    const { evidence, cleanup } = await run([purchase]);
    try {
      expect(pageOf(evidence, '/').status).toBe('complete');
      const account = pageOf(evidence, 'journey:purchase/account');
      expect(account.status).toBe('failed');
      const issue = account.issues.find((i) => i.code === 'journey-step-failed');
      expect(issue?.message).toContain('step 5 of 11');
      expect(issue?.message).toContain('waitFor');
      for (const key of ['journey:purchase/cart', 'journey:purchase/checkout']) {
        const p = pageOf(evidence, key);
        expect(p.status).toBe('failed');
        expect(p.issues[0]?.code).toBe('journey-not-reached');
      }
      expect(JSON.stringify(evidence)).not.toContain('wrong-password-123');
      expect(evidence.sites[0]?.status).toBe('partial');
    } finally {
      await cleanup();
    }
  }, 120_000);

  it('reports the selector but never the value of a failing fill step', async () => {
    process.env[SECRET_VAR] = JOURNEY_PASSWORD;
    const journey = { name: 'bad-fill', steps: [{ type: 'goto', url: '/login' }, { type: 'fill', selector: '#nope', value: '${' + SECRET_VAR + '}', timeoutMs: 700 }, { type: 'capture', name: 'x' }] };
    const { evidence, cleanup } = await run([journey]);
    try {
      const p = pageOf(evidence, 'journey:bad-fill/x');
      const message = p.issues.map((i) => i.message).join('\n');
      expect(message).toContain('step 2 of 3');
      expect(message).toContain('fill "#nope"');
      expect(message).not.toContain(JOURNEY_PASSWORD);
    } finally {
      await cleanup();
    }
  }, 60_000);

  it('fails the journey up front when a referenced secret is not set (names only, no browser steps)', async () => {
    const { evidence, cleanup } = await run([purchase]);
    try {
      const p = pageOf(evidence, 'journey:purchase/account');
      expect(p.status).toBe('failed');
      expect(p.issues[0]?.code).toBe('journey-secret-missing');
      expect(p.issues[0]?.message).toContain(SECRET_VAR);
      expect(state.loginBodies).toHaveLength(0);
    } finally {
      await cleanup();
    }
  }, 60_000);

  it('refuses secrets shorter than 8 characters', async () => {
    process.env[SECRET_VAR] = 'short';
    const { evidence, cleanup } = await run([purchase]);
    try {
      expect(pageOf(evidence, 'journey:purchase/account').issues[0]?.code).toBe('journey-secret-too-short');
      expect(JSON.stringify(evidence)).not.toContain('"short"');
    } finally {
      await cleanup();
    }
  }, 60_000);

  describe('submit guard', () => {
    const toCheckout = [
      ...loginSteps,
      { type: 'click', selector: '#to-checkout', timeoutMs: 800 },
    ];
    // After login /account has no #to-checkout; go through the cart.
    const steps = (pay: Record<string, unknown>): unknown[] => [
      ...loginSteps,
      { type: 'goto', url: '/cart' },
      toCheckout[toCheckout.length - 1],
      { type: 'waitFor', url: '**/checkout', timeoutMs: 4000 },
      { type: 'capture', name: 'checkout' },
      pay,
      { type: 'waitFor', selector: 'h1', timeoutMs: 2000 },
      { type: 'capture', name: 'paid' },
    ];

    it('blocks clicking the submit button of a payment form unless allowSubmit is set', async () => {
      process.env[SECRET_VAR] = JOURNEY_PASSWORD;
      const { evidence, cleanup } = await run([{ name: 'guarded', steps: steps({ type: 'click', selector: '#pay' }) }]);
      try {
        expect(pageOf(evidence, 'journey:guarded/checkout').status).toBe('complete');
        const paid = pageOf(evidence, 'journey:guarded/paid');
        expect(paid.status).toBe('failed');
        expect(paid.issues.map((i) => i.message).join(' ')).toContain('allowSubmit');
        expect(state.payPosts).toHaveLength(0);
      } finally {
        await cleanup();
      }
    }, 120_000);

    it('blocks pressing Enter in a payment form field too', async () => {
      process.env[SECRET_VAR] = JOURNEY_PASSWORD;
      const { evidence, cleanup } = await run([{ name: 'enter', steps: steps({ type: 'press', selector: '[name=cardnumber]', key: 'Enter' }) }]);
      try {
        expect(pageOf(evidence, 'journey:enter/paid').status).toBe('failed');
        expect(state.payPosts).toHaveLength(0);
      } finally {
        await cleanup();
      }
    }, 120_000);

    it('submits only with an explicit allowSubmit: true', async () => {
      process.env[SECRET_VAR] = JOURNEY_PASSWORD;
      const { evidence, cleanup } = await run([{ name: 'allowed', steps: steps({ type: 'click', selector: '#pay', allowSubmit: true }) }]);
      try {
        expect(pageOf(evidence, 'journey:allowed/paid').status).toBe('complete');
        expect(state.payPosts).toHaveLength(1);
      } finally {
        await cleanup();
      }
    }, 120_000);

    it('does not block a login form submit', async () => {
      process.env[SECRET_VAR] = JOURNEY_PASSWORD;
      const { evidence, cleanup } = await run([{ name: 'login-only', steps: [...loginSteps, { type: 'capture', name: 'in' }] }]);
      try {
        expect(pageOf(evidence, 'journey:login-only/in').status).toBe('complete');
      } finally {
        await cleanup();
      }
    }, 60_000);
  });

  it('does not follow navigation to hosts outside the site domain', async () => {
    process.env[SECRET_VAR] = JOURNEY_PASSWORD;
    const journey = {
      name: 'offsite',
      steps: [...loginSteps, { type: 'goto', url: '/cart' }, { type: 'click', selector: '#offsite', timeoutMs: 3000 }, { type: 'capture', name: 'x' }],
    };
    const { evidence, cleanup } = await run([journey]);
    try {
      const p = pageOf(evidence, 'journey:offsite/x');
      expect(p.status).toBe('failed');
      expect(p.issues.map((i) => i.message).join(' ')).toMatch(/blocked|outside/);
      expect(server.hits.some((h) => h.includes('/elsewhere.html'))).toBe(false);
    } finally {
      await cleanup();
    }
  }, 60_000);

  it('starts from a saved authenticated session (storageState) without scripted login', async () => {
    const [name, value] = SESSION_COOKIE.split('=');
    const fresh = await makeProject(server.port, {
      sites: [site([{ name: 'saved', storageState: 'sessions/shop.json', steps: [{ type: 'goto', url: '/checkout' }, { type: 'capture', name: 'checkout' }] }])],
    });
    try {
      await mkdir(join(fresh.dir, 'sessions'), { recursive: true });
      await writeFile(
        join(fresh.dir, 'sessions', 'shop.json'),
        JSON.stringify({ cookies: [{ name, value, domain: 'shop.test', path: '/', expires: -1, httpOnly: true, secure: false, sameSite: 'Lax' }], origins: [] }),
      );
      const evidence = await collectEvidence(buildCollectRequest(fresh.resolved, selectSites(fresh.resolved)));
      const p = pageOf(evidence, 'journey:saved/checkout');
      expect(p.status).toBe('complete');
      expect(scriptUrls(p).some((u) => u.endsWith('/pay-loggedin.js'))).toBe(true);
    } finally {
      await fresh.cleanup();
    }
  }, 60_000);

  it('reports a missing storageState file as a failed journey', async () => {
    const { evidence, cleanup } = await run([{ name: 'nofile', storageState: 'does-not-exist.json', steps: [{ type: 'goto', url: '/cart' }, { type: 'capture', name: 'cart' }] }]);
    try {
      const p = pageOf(evidence, 'journey:nofile/cart');
      expect(p.status).toBe('failed');
      expect(p.issues[0]?.code).toBe('journey-context-failed');
    } finally {
      await cleanup();
    }
  }, 60_000);

  it('enforces the per-journey timeout', async () => {
    process.env[SECRET_VAR] = JOURNEY_PASSWORD;
    const journey = { name: 'slowj', timeoutMs: 5000, steps: [{ type: 'goto', url: '/login' }, { type: 'waitFor', selector: '#never', timeoutMs: 30000 }, { type: 'capture', name: 'x' }] };
    const started = Date.now();
    const { evidence, cleanup } = await run([journey]);
    try {
      expect(Date.now() - started).toBeLessThan(20_000);
      expect(pageOf(evidence, 'journey:slowj/x').status).toBe('failed');
    } finally {
      await cleanup();
    }
  }, 60_000);
});
