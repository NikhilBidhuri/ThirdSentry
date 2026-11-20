import { errors as playwrightErrors, type Browser, type BrowserContext, type Locator, type Page, type Response } from 'playwright';
import type { Limits } from '../config/schema.js';
import type { ResolvedJourney, ResolvedPage, ResolvedSite } from '../config/loader.js';
import { journeyHostAllowed, journeySecretNames, substituteSecrets, type JourneyStep } from '../config/journeys.js';
import { redactText, redactUrl } from '../security/redaction.js';
import type { Issue, PageEvidence, PageStatus } from '../types/evidence.js';
import { getLogger } from '../utils/logger.js';
import { createIsolatedContext } from './browser-manager.js';
import type { BrowserProfile } from './browser-profiles.js';
import { clampUrl, type PageEvidenceBudget, type ScanEvidenceBudget } from './evidence-budget.js';
import { SecretRedactor } from './journey-secrets.js';
import type { NetworkCollector } from './network-collector.js';
import {
  attachPageListeners,
  createCollectors,
  degrader,
  failedPage,
  installInstrumentation,
  settlePage,
  snapshotAndBuildEvidence,
  type PageObservations,
} from './page-scanner.js';
import { withTimeout } from './network-collector.js';

/**
 * Runs one journey (login -> cart -> checkout ...) in a single browser
 * context, so cookies persist across steps, and returns one PageEvidence per
 * `capture` step, in order.
 *
 * Reuse: the same collectors as plain pages observe the page. Network and
 * script activity is split into segments: the evidence of a capture covers
 * what happened since the previous capture (a fresh network collector and a
 * reset resource collector per segment) plus a DOM snapshot at capture time.
 *
 * SAFETY
 *  - Never throws: a failing step marks the next capture failed and the later
 *    ones "not reached"; earlier captures stay valid.
 *  - Issues about steps contain the step index, type and selector, never
 *    values, and never raw Playwright messages (whose call logs echo the
 *    text that was typed).
 *  - Secrets come from the worker's environment, are length-checked, and are
 *    redacted from all emitted evidence (see journey-secrets.ts).
 *  - Top-level navigation is restricted to the site's registrable domain
 *    (plus journey.allowedHosts) by a request route, in addition to the egress
 *    proxy that every connection goes through.
 *  - Clicking a submit button of a payment-like form (or pressing Enter in
 *    one) requires `allowSubmit: true`.
 */

export interface JourneyRunRequest {
  readonly browser: Browser;
  readonly profile: BrowserProfile;
  readonly site: ResolvedSite;
  readonly journey: ResolvedJourney;
  readonly limits: Limits;
  readonly serviceWorkers: { strategy: 'block' | 'allow'; probeBlockedRegistrations: boolean };
  /** Absolute scan deadline (epoch ms). */
  readonly deadline: number;
  readonly budget: ScanEvidenceBudget;
  /** Environment holding the secret variables (default: process.env). */
  readonly env?: Readonly<Record<string, string | undefined>>;
}

class StepError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

/**
 * In-page check used by the submit guard. Returns whether `el` would submit a
 * form and whether that form looks like a payment form (card fields, hosted
 * payment iframes, or a pay/charge/purchase/order action).
 */
const GUARD_BODY = `
  const ctl = el.closest('button, input[type=submit], input[type=image], input[type=button]') || el;
  const form = ctl.form || ctl.closest('form');
  if (!form) return { submit: false, payment: false };
  const tag = ctl.tagName.toLowerCase();
  const type = (ctl.getAttribute('type') || '').toLowerCase();
  let submit;
  if (key) {
    submit = (key === 'Enter' || key === 'NumpadEnter') && (tag === 'select' || (tag === 'input' && !['button','submit','image','reset','checkbox','radio','file'].includes(type)));
  } else {
    submit = (tag === 'button' && (type === '' || type === 'submit')) || (tag === 'input' && (type === 'submit' || type === 'image'));
  }
  const card = /card.?(number|num|no|cvc|cvv|exp)|cc.?(num|number|csc|cvc|cvv|exp)|cvv|cvc|csc/i;
  const frame = /card|payment|stripe|braintree|adyen|paypal|hosted.?fields|secure.?fields/i;
  const action = /(^|[\\/_-])(pay|payment|payments|charge|purchase|place-?order)([\\/_.?-]|$)/i;
  let payment = false;
  for (const f of form.elements) {
    const ac = (f.getAttribute && f.getAttribute('autocomplete')) || '';
    if (/(^|\\s)cc-/i.test(ac)) payment = true;
    if (card.test((f.getAttribute && f.getAttribute('name')) || '') || card.test(f.id || '')) payment = true;
  }
  for (const fr of form.querySelectorAll('iframe')) {
    if (frame.test((fr.getAttribute('src') || '') + ' ' + (fr.getAttribute('name') || '') + ' ' + (fr.getAttribute('title') || ''))) payment = true;
  }
  if (action.test(form.getAttribute('action') || '')) payment = true;
  return { submit, payment };
`;

interface GuardVerdict {
  readonly submit: boolean;
  readonly payment: boolean;
}

/** Built from a string because this file is compiled without DOM types; Playwright serialises it into the page. */
// eslint-disable-next-line @typescript-eslint/no-implied-eval -- GUARD_BODY is a constant; nothing from the config or the page is ever compiled
const guardFn = new Function('el', 'key', GUARD_BODY) as (el: never, key: string | undefined) => GuardVerdict;

function describeStep(step: JourneyStep): string {
  const sel = 'selector' in step && step.selector ? ` ${JSON.stringify(step.selector.slice(0, 200))}` : '';
  return `${step.type}${step.type === 'goto' ? ` ${JSON.stringify(redactUrl(step.url).slice(0, 200))}` : sel}`;
}

/** Map any error to a safe code and message. Raw Playwright text is never used: call logs echo typed values. */
function classify(error: unknown, timeoutMs: number): StepError {
  if (error instanceof StepError) return error;
  const text = error instanceof Error ? error.message : String(error);
  if (error instanceof playwrightErrors.TimeoutError || /Timeout \d+ms exceeded/.test(text)) {
    return new StepError('step-timeout', `element or condition not found/actionable within ${timeoutMs}ms`);
  }
  if (/strict mode violation/.test(text)) return new StepError('selector-ambiguous', 'selector matches more than one element');
  const net = /net::(ERR_[A-Z_]+)/.exec(text);
  if (net) return new StepError('navigation-failed', `navigation failed (${net[1] ?? 'network error'})`);
  if (/has been closed|Target closed/.test(text)) return new StepError('browser-closed', 'the page or browser was closed');
  if (/not a checkbox|not an <select>|Element is not/.test(text)) return new StepError('wrong-element', 'the element does not support this step type');
  return new StepError('step-error', 'the step failed (details withheld: they may contain typed values)');
}

function toGlob(url: string): string {
  return url.startsWith('/') ? `**${url}` : url;
}

export async function runJourney(req: JourneyRunRequest): Promise<PageEvidence[]> {
  const { journey, site, limits } = req;
  const log = getLogger('journey').child({ site: site.name, journey: journey.name });
  const scan = site.scan;
  const captures = journey.captures;
  const env = req.env ?? process.env;
  const journeyStarted = Date.now();
  const journeyDeadline = Math.min(req.deadline, journeyStarted + journey.timeoutMs);
  const redactor = new SecretRedactor();
  const outputs: PageEvidence[] = [];
  const startedAt = new Date().toISOString();

  const finishAll = (issue: Issue): PageEvidence[] =>
    captures.map((c, i) => failedPage(c, startedAt, [i === 0 ? issue : notReached(journey.name, issue.code)]));

  // --- Secrets: resolved up front, before any browser context exists --------
  const names = journeySecretNames([{ journeys: [journey] }]);
  const missing = names.filter((n) => env[n] === undefined || env[n] === '');
  if (missing.length > 0) {
    return finishAll({
      level: 'error',
      code: 'journey-secret-missing',
      message: `Journey "${journey.name}" needs environment variable(s) ${missing.join(', ')}, which are not set in the browser worker (see docs/configuration.md#journey-secrets)`,
    });
  }
  const tooShort = names.filter((n) => (env[n] ?? '').length < 8);
  if (tooShort.length > 0) {
    return finishAll({
      level: 'error',
      code: 'journey-secret-too-short',
      message: `Secret variable(s) ${tooShort.join(', ')} are shorter than 8 characters; such values cannot be redacted reliably. Use a longer test-account password or a literal value for non-secret fields`,
    });
  }
  for (const n of names) redactor.add(env[n] ?? '');

  const safeText = (s: string): string => redactor.text(redactText(s, 500));
  const finalize = (page: PageEvidence): PageEvidence => {
    const before = redactor.hits;
    const clean = redactor.deep(page);
    if (redactor.hits > before) {
      clean.issues = [
        ...clean.issues,
        { level: 'warning', code: 'secret-redacted', message: 'A secret value typed by this journey appeared in observed content (for example a URL or console message) and was redacted' },
      ];
    }
    return clean;
  };

  let context: BrowserContext | undefined;
  try {
    context = await createIsolatedContext(req.browser, {
      profile: req.profile,
      serviceWorkers: req.serviceWorkers.strategy,
      ...(scan.userAgent ? { userAgent: scan.userAgent } : {}),
      ...(journey.storageState ? { storageState: journey.storageState } : {}),
    });
  } catch {
    return finishAll({
      level: 'error',
      code: 'journey-context-failed',
      message: journey.storageState
        ? `Could not start the browser context; check that the storageState file exists in the scanner and is valid JSON (${journey.storageState})`
        : 'Could not start the browser context for this journey',
    }).map(finalize);
  }

  let failure: Issue | undefined;
  try {
    const siteHost = new URL(site.url).hostname;
    const remaining = (): number => journeyDeadline - Date.now();
    const timeoutFor = (step: JourneyStep): number => {
      const left = remaining();
      if (left <= 0) throw new StepError('journey-timeout', `journey time limit (${journey.timeoutMs}ms or the scan deadline) reached`);
      const own = 'timeoutMs' in step && step.timeoutMs ? step.timeoutMs : scan.timeout;
      return Math.max(500, Math.min(own, left));
    };

    // --- Collectors and one page; segments are renewed after each capture --
    let budget: PageEvidenceBudget = req.budget.page(limits.maxEvidenceBytesPerPage);
    const { resources, makeNetwork } = createCollectors(limits, budget);
    await installInstrumentation(context, resources, limits);
    const page: Page = await context.newPage();
    resources.attachPage(page);
    page.setDefaultTimeout(scan.timeout);
    page.setDefaultNavigationTimeout(scan.timeout);

    const blockedHosts: string[] = [];
    await context.route('**/*', (route) => {
      const request = route.request();
      let topLevel: boolean;
      try {
        topLevel = request.isNavigationRequest() && request.frame() === page.mainFrame();
      } catch {
        topLevel = false; // service worker requests have no frame
      }
      if (!topLevel) return route.fallback();
      let allowed: boolean;
      try {
        const u = new URL(request.url());
        allowed = (u.protocol === 'http:' || u.protocol === 'https:') && journeyHostAllowed(u.hostname, siteHost, journey.allowedHosts);
        if (!allowed && blockedHosts.length < 5) blockedHosts.push(u.hostname || u.protocol);
      } catch {
        allowed = false;
      }
      return allowed ? route.fallback() : route.abort('blockedbyclient');
    });

    let lastDoc: Response | null = null;
    page.on('response', (response) => {
      try {
        if (response.request().isNavigationRequest() && response.frame() === page.mainFrame()) lastDoc = response;
      } catch {
        /* service worker or detached frame */
      }
    });

    const filled = new Set<string>();
    let obs: PageObservations = { consoleErrors: [], pageErrors: [] };
    attachPageListeners(page, () => obs);

    interface Segment {
      startedAt: string;
      issues: Issue[];
      state: { status: PageStatus };
      network: NetworkCollector;
    }
    const newSegment = (): Segment => {
      budget = req.budget.page(limits.maxEvidenceBytesPerPage);
      resources.reset(budget);
      obs = { consoleErrors: [], pageErrors: [] };
      const network = makeNetwork(page, budget);
      network.attach(context);
      return { startedAt: new Date().toISOString(), issues: [], state: { status: 'complete' }, network };
    };
    let segment = newSegment();

    const locate = (selector: string): Locator => page.locator(selector);

    const guard = async (locator: Locator, key: string | undefined, step: JourneyStep, timeout: number): Promise<void> => {
      const verdict = await locator.evaluate(guardFn, key, { timeout });
      if (verdict.submit && verdict.payment && !('allowSubmit' in step && step.allowSubmit)) {
        throw new StepError(
          'submit-guard',
          'this would submit a payment-like form; set allowSubmit: true only for test cards against a payment sandbox, never with live payment credentials',
        );
      }
    };

    const capture = async (step: Extract<JourneyStep, { type: 'capture' }>): Promise<void> => {
      const target: ResolvedPage | undefined = captures[outputs.length];
      if (!target) return;
      const degrade = degrader(segment.state);
      const currentUrl = page.url();
      if (currentUrl === 'about:blank') {
        segment.issues.push({ level: 'error', code: 'capture-without-page', message: `Capture "${step.name}" was reached before any page was loaded; add a "goto" step first` });
        degrade('failed');
      } else {
        await settlePage(page, scan, req.deadline, segment.issues, degrade);
        const status = lastDoc?.status();
        if (status !== undefined && status >= 400) {
          segment.issues.push({ level: 'error', code: 'http-error', message: `Page returned HTTP ${status}` });
          degrade('failed');
        }
      }
      const mask = [...filled].map(locate);
      mask.push(page.locator('input[type=password]'));
      const evidence = await snapshotAndBuildEvidence({
        page,
        context,
        target: { key: target.key, url: clampUrl(currentUrl), sensitive: target.sensitive },
        scan,
        limits,
        serviceWorkers: req.serviceWorkers,
        deadline: req.deadline,
        startedAt: segment.startedAt,
        docResponse: lastDoc,
        issues: segment.issues,
        obs,
        state: segment.state,
        network: segment.network,
        resources,
        budget,
        screenshotMask: mask,
        log,
      });
      outputs.push(finalize(evidence));
      segment = newSegment();
    };

    const exec = async (step: JourneyStep): Promise<void> => {
      if (step.type === 'capture') return capture(step);
      const timeout = timeoutFor(step);
      switch (step.type) {
        case 'goto': {
          const response = await page.goto(step.url, { waitUntil: scan.waitUntil === 'networkidle' ? 'load' : scan.waitUntil, timeout });
          if (response && response.status() >= 400) throw new StepError('http-error', `navigation returned HTTP ${response.status()}`);
          return;
        }
        case 'click': {
          const target = locate(step.selector);
          await guard(target, undefined, step, timeout);
          await target.click({ timeout });
          await page.waitForLoadState('load', { timeout: Math.min(timeout, 15_000) }).catch(() => undefined);
          return;
        }
        case 'fill': {
          const { value, missing: gone } = substituteSecrets(step.value, env);
          if (gone.length > 0) throw new StepError('secret-missing', `secret variable ${gone.join(', ')} is not set`);
          filled.add(step.selector);
          await locate(step.selector).fill(value, { timeout });
          return;
        }
        case 'select':
          await locate(step.selector).selectOption(step.value, { timeout });
          return;
        case 'check':
          await locate(step.selector).setChecked(step.checked, { timeout });
          return;
        case 'press': {
          const target = step.selector ? locate(step.selector) : page.locator(':focus');
          if (step.selector || (await target.count()) > 0) await guard(target.first(), step.key, step, timeout);
          if (step.selector) await target.press(step.key, { timeout });
          else await page.keyboard.press(step.key);
          await page.waitForLoadState('load', { timeout: Math.min(timeout, 15_000) }).catch(() => undefined);
          return;
        }
        case 'waitFor': {
          if (step.selector) await locate(step.selector).waitFor({ state: 'visible', timeout });
          else if (step.url) await page.waitForURL(toGlob(step.url), { timeout });
          else if (step.loadState) await page.waitForLoadState(step.loadState, { timeout });
          return;
        }
      }
    };

    for (const [index, step] of journey.steps.entries()) {
      log.debug({ step: index, type: step.type }, 'journey step');
      try {
        await exec(step);
        // Navigation (clicks, redirects) must not leave the allowed hosts.
        const u = page.url();
        if (u !== 'about:blank') {
          const host = new URL(u).hostname;
          if (!journeyHostAllowed(host, siteHost, journey.allowedHosts)) throw new StepError('off-site', `the page navigated to ${host}, outside the site's domain`);
        }
      } catch (error) {
        const cause = classify(error, 'timeoutMs' in step && step.timeoutMs ? step.timeoutMs : scan.timeout);
        const blocked = cause.code !== 'off-site' && blockedHosts.length > 0 ? ` (navigation to ${blockedHosts.join(', ')} was blocked: outside the allowed hosts)` : '';
        failure = {
          level: 'error',
          code: 'journey-step-failed',
          message: safeText(`Journey "${journey.name}" step ${index + 1} of ${journey.steps.length} (${describeStep(step)}) failed: ${cause.message}${blocked}`),
        };
        log.warn({ step: index, type: step.type, code: cause.code }, 'journey step failed');
        break;
      }
    }
    segment.network.detach();
    if (failure) {
      const rest = captures.slice(outputs.length);
      rest.forEach((c, i) => {
        const issues: Issue[] = i === 0 ? [failure as Issue, ...segment.issues] : [notReached(journey.name, 'journey-step-failed')];
        outputs.push(finalize(failedPage(c, segment.startedAt, issues)));
      });
    }
  } catch (error) {
    // Setup errors (instrumentation, page creation). Steps never reach here.
    log.warn({ err: safeText(error instanceof Error ? error.message.split('\n')[0] ?? '' : String(error)) }, 'journey setup failed');
    const issue: Issue = { level: 'error', code: 'journey-error', message: `Journey "${journey.name}" could not be run: ${safeText(error instanceof Error ? error.message.split('\n')[0] ?? 'error' : 'error')}` };
    for (const c of captures.slice(outputs.length)) outputs.push(finalize(failedPage(c, startedAt, [issue])));
  } finally {
    await withTimeout(context.close(), 15_000).catch(() => undefined);
  }
  // Defensive: always exactly one evidence entry per configured capture.
  while (outputs.length < captures.length) {
    const c = captures[outputs.length] as ResolvedPage;
    outputs.push(failedPage(c, startedAt, [notReached(journey.name, 'journey-ended')]));
  }
  return outputs.slice(0, captures.length);
}

function notReached(journey: string, because: string): Issue {
  return {
    level: 'error',
    code: 'journey-not-reached',
    message: `Not reached: an earlier step of journey "${journey}" failed or the journey could not start (${because}); this capture was not taken`,
  };
}
