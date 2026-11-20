import { spawn } from 'node:child_process';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { PageEvidenceBudget, ScanEvidenceBudget } from '../../src/browser/evidence-budget.js';
import { DirectorySink, MemorySink, writeEvidenceJson, PART_FILES } from '../../src/browser/evidence-sink.js';
import { discoverExternalScripts } from '../../src/discovery/script-discovery.js';
import { assembleEvidence } from '../../src/security/evidence-assembly.js';
import { killProcessTree, validateEvidence } from '../../src/security/worker-sandbox.js';
import { BodyStatusSchema, type DomScriptEvidence, type PageEvidence, type ScanEvidence } from '../../src/types/evidence.js';
import { readJsonFile } from '../../src/utils/fs.js';
import { tempDir } from '../helpers.js';
import type { CollectRequest } from '../../src/browser/collector.js';

function page(key: string, status: PageEvidence['status'] = 'complete'): PageEvidence {
  return {
    pageKey: key,
    pageUrl: `http://shop.test/${key}`,
    sensitive: false,
    status,
    issues: [],
    startedAt: 't',
    finishedAt: 't',
    documentHeaders: {},
    cspHeaders: [],
    cspReportOnlyHeaders: [],
    frames: [],
    scriptResponses: [],
    domScripts: [],
    blobs: [],
    workers: [],
    requests: [],
    requestsDropped: 0,
    scriptsDropped: 0,
    consoleErrors: [],
    pageErrors: [],
  };
}

const header = {
  schemaVersion: 1 as const,
  scanId: 's',
  toolVersion: '0',
  startedAt: 't',
  isolation: 'process' as const,
  serviceWorkerStrategy: 'block' as const,
  issues: [],
};
const start = { name: 'a', url: 'http://shop.test/', profile: 'desktop-chromium', browserName: 'chromium', emulation: '', startedAt: 't' };
const summary = { ...start, browserVersion: '1', status: 'complete' as const, issues: [], finishedAt: 't', proxyEvents: [], proxyEventsDropped: 0 };

const req = (sites: string[][]): CollectRequest =>
  ({
    sites: sites.map((pages, i) => ({
      name: `s${i}`,
      url: 'http://shop.test/',
      profile: 'desktop-chromium',
      pages: pages.map((k) => ({ key: k, url: `http://shop.test/${k}`, sensitive: false })),
    })),
  }) as unknown as CollectRequest;

describe('evidence budget', () => {
  it('refuses content past the page and scan budgets and counts refusals', () => {
    const scan = new ScanEvidenceBudget(1000);
    const a = new PageEvidenceBudget(600, scan);
    expect(a.tryReserve(500)).toBe(true);
    expect(a.tryReserve(500)).toBe(false);
    expect(a.refused).toBe(1);
    const b = new PageEvidenceBudget(600, scan);
    expect(b.tryReserve(400)).toBe(true);
    expect(b.tryReserve(200)).toBe(false); // scan budget (1000) exhausted: 500 + 400 + 200
    expect(b.scanExhausted).toBe(true);
    expect(BodyStatusSchema.parse('budget-exceeded')).toBe('budget-exceeded');
  });
});

describe('incremental evidence', () => {
  const dirs: string[] = [];
  afterEach(async () => {
    await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
  });
  async function dir(): Promise<string> {
    const d = await tempDir('asm-');
    dirs.push(d);
    return d;
  }

  it('assembles a normal run identically to the memory sink', async () => {
    const d = await dir();
    const sink = new DirectorySink(d);
    await sink.begin(header);
    await sink.siteStarted(0, start);
    await sink.page(0, 0, page('p0'));
    await sink.siteFinished(0, summary);
    await sink.end({ finishedAt: 'f', issues: [] });
    const evidence = await assembleEvidence(d, req([['p0']]), { maxBytes: 1e8 });
    expect(evidence.issues).toEqual([]);
    expect(evidence.sites[0]?.pages[0]?.pageKey).toBe('p0');
    expect(() => validateEvidence(evidence)).not.toThrow();
    const mem = new MemorySink();
    await mem.begin(header);
    await mem.siteStarted(0);
    await mem.page(0, 0, page('p0'));
    await mem.siteFinished(0, summary);
    await mem.end({ finishedAt: 'f', issues: [] });
    expect(mem.result().sites[0]?.pages).toEqual(evidence.sites[0]?.pages);
  });

  it('keeps completed sites and marks the in-flight page and unreached sites failed when the worker dies', async () => {
    const d = await dir();
    const sink = new DirectorySink(d);
    await sink.begin(header);
    await sink.siteStarted(0, start);
    await sink.page(0, 0, page('a0'));
    await sink.siteFinished(0, summary);
    await sink.siteStarted(1, { ...start, name: 'b' });
    await sink.page(1, 0, page('b0')); // b1 in flight, worker killed, no summary / footer
    const evidence = await assembleEvidence(d, req([['a0'], ['b0', 'b1', 'b2'], ['c0']]), { maxBytes: 1e8, failure: 'timeout' });
    expect(() => validateEvidence(evidence)).not.toThrow();
    expect(evidence.sites[0]?.status).toBe('complete');
    expect(evidence.sites[1]?.pages.map((p) => [p.pageKey, p.status])).toEqual([
      ['b0', 'complete'],
      ['b1', 'failed'],
      ['b2', 'failed'],
    ]);
    expect(evidence.sites[1]?.pages[1]?.issues[0]?.code).toBe('worker-died-during-page');
    expect(evidence.sites[1]?.pages[2]?.issues[0]?.code).toBe('page-not-scanned');
    expect(evidence.sites[1]?.status).toBe('partial');
    expect(evidence.sites[2]?.status).toBe('failed');
    expect(evidence.issues.some((i) => i.code === 'worker-incomplete')).toBe(true);
  });

  it('discards a corrupt page part but keeps the rest', async () => {
    const d = await dir();
    const sink = new DirectorySink(d);
    await sink.begin(header);
    await sink.siteStarted(0, start);
    await sink.page(0, 0, page('p0'));
    await writeFile(join(d, PART_FILES.page(0, 1)), '{ not json');
    await sink.siteFinished(0, summary);
    await sink.end({ finishedAt: 'f', issues: [] });
    const evidence = await assembleEvidence(d, req([['p0', 'p1']]), { maxBytes: 1e8 });
    expect(evidence.sites[0]?.pages[0]?.status).toBe('complete');
    expect(evidence.sites[0]?.pages[1]?.status).toBe('failed');
    expect(evidence.sites[0]?.issues.some((i) => i.code === 'page-evidence-invalid')).toBe(true);
  });

  it('fails loudly when not even the header exists', async () => {
    const d = await dir();
    await expect(assembleEvidence(d, req([['p']]), { maxBytes: 1e8 })).rejects.toThrow(/no evidence/);
  });

  it('writeEvidenceJson output is the classic single-file format', async () => {
    const d = await dir();
    await mkdir(d, { recursive: true });
    const evidence: ScanEvidence = { ...header, finishedAt: 'f', sites: [{ ...summary, pages: [page('p0'), page('p1')] }] };
    const file = join(d, 'e.json');
    await writeEvidenceJson(file, evidence);
    expect(await readJsonFile(file)).toEqual(JSON.parse(JSON.stringify(evidence)));
  });
});

describe('killProcessTree', () => {
  it('kills the process and its descendants', async () => {
    const code =
      "const c=require('child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'inherit'});console.log(c.pid);setInterval(()=>{},1000)";
    const child = spawn(process.execPath, ['-e', code], { detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'inherit'] });
    const grandchild = await new Promise<number>((resolve) => child.stdout.once('data', (b: Buffer) => resolve(Number(b.toString().trim()))));
    const exited = new Promise((resolve) => child.once('exit', resolve));
    await killProcessTree(child.pid as number);
    await exited;
    await new Promise((r) => setTimeout(r, 500));
    expect(() => process.kill(grandchild, 0)).toThrow();
  }, 20_000);
});

describe('page-reported data cannot remove network signals', () => {
  const dom = (over: Partial<DomScriptEvidence>): DomScriptEvidence => ({
    kind: 'external',
    src: 'http://cdn.test/a.js',
    domPath: 'html>head>script',
    frameUrl: 'http://shop.test/',
    isMainFrame: true,
    insertedByScript: false,
    observedVia: 'mutation',
    timestamp: 't',
    ...over,
  });
  const run = (domScripts: DomScriptEvidence[]) => {
    const p = page('/');
    p.domScripts = domScripts;
    p.scriptResponses = [
      {
        url: 'http://cdn.test/a.js',
        redirectChain: [],
        method: 'GET',
        requestResourceType: 'script',
        status: 200,
        contentType: 'application/javascript',
        responseHeaders: {},
        bodyStatus: 'captured',
        bodyBase64: Buffer.from('console.log(1)').toString('base64'),
        isMainFrame: true,
        fromServiceWorker: false,
        source: 'page-network',
        timestamp: 't',
      },
    ];
    return discoverExternalScripts(p, { pageKey: '/', ignoreQueryParams: [], maxResourceBytes: 1e6 })[0];
  };

  it('treats any runtime-injection report as dynamic', () => {
    expect(run([dom({ insertedByScript: true }), dom({ insertedByScript: false })])?.dynamic).toBe(true);
  });

  it('ignores an integrity value reported only by the in-page hooks', () => {
    const forged = run([dom({ integrity: 'sha256-AAAA' })]);
    expect(forged?.integrity).toBeUndefined();
    const corroborated = run([dom({ integrity: 'sha256-AAAA' }), dom({ observedVia: 'snapshot', integrity: 'sha256-AAAA' })]);
    expect(corroborated?.integrity).toBe('sha256-AAAA');
  });
});
