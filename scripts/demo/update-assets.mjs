#!/usr/bin/env node
// `npm run demo:assets`: regenerate the README media from a real demo run.
//
//   docs/assets/demo.gif             terminal + report walkthrough (real CLI output)
//   docs/assets/sample-report.html   the HTML report of the compromised scan
//   docs/assets/report-screenshot.png
//
// It runs the same scenario as `npm run demo` (demo/site/server.mjs) on a
// fixed port so the committed files are stable, captures the coloured CLI
// output, plays it back in scripts/demo/stage.html in headless Chromium and
// encodes the screenshots as a GIF with gifenc (pure JS, no ffmpeg needed).

import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import gifenc from 'gifenc';
import { PNG } from 'pngjs';
import { chromium } from 'playwright';
import { stringify } from 'yaml';
import { createDemoServer, demoConfig } from '../../demo/site/server.mjs';

const { GIFEncoder, quantize, applyPalette } = gifenc;

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const WORK = join(ROOT, 'demo', '.work-assets');
const ASSETS = join(ROOT, 'docs', 'assets');
const BIN = join(ROOT, 'dist', 'cli', 'bin.js');
const PORT = 8484;
const WIDTH = 880;
const HEIGHT = 540;

const WORK_RE = new RegExp(`${WORK.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[\\\\/]?`, 'gi');
/** Remove the absolute work directory from CLI output and the report (paths become relative). */
const stripWork = (s) => s.replace(WORK_RE, '');
const log = (msg) => process.stdout.write(`${msg}\n`);

// ---------------------------------------------------------------------------
// 1. Run the scenario and capture coloured output per step

function cli(args) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env, NODE_OPTIONS: `--import=${pathToFileURL(join(ROOT, 'scripts', 'demo', 'force-tty.mjs')).href}` };
    delete env.NO_COLOR;
    const child = spawn(process.execPath, [BIN, '--quiet', '--config', join(WORK, 'thirdsentry.yml'), ...args], { cwd: WORK, env, stdio: ['ignore', 'pipe', 'ignore'] });
    let stdout = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.on('error', reject);
    child.on('exit', (code) => resolve({ code: code ?? 1, stdout: stdout.replaceAll(`${WORK}\\`, '').replaceAll(`${WORK}/`, '') }));
  });
}

async function runScenario() {
  if (!existsSync(BIN)) {
    const build = spawnSync('npm', ['run', 'build'], { cwd: ROOT, stdio: 'inherit', shell: true });
    if (build.status !== 0) throw new Error('build failed');
  }
  await rm(WORK, { recursive: true, force: true });
  await mkdir(WORK, { recursive: true });
  const shop = createDemoServer();
  await shop.start(PORT);
  try {
    await writeFile(join(WORK, 'thirdsentry.yml'), stringify(demoConfig(PORT)));
    log('scan (clean)...');
    const first = await cli(['scan', '--allow-missing-baseline', '--fail-on', 'none', '--format', 'json']);
    log('baseline...');
    const baseline = await cli(['baseline', '--yes', '--reason', 'demo: reviewed the clean shop', '--approved-by', 'demo']);
    shop.setState('compromised');
    log('scan (compromised)...');
    const attack = await cli(['scan', '--fail-on', 'high', '--format', 'json,html', '--output', 'report']);
    if (attack.code !== 1) throw new Error(`expected the compromised scan to exit 1, got ${attack.code}`);
    return { first, baseline, attack, reportPath: join(WORK, 'report', 'report.html') };
  } finally {
    await shop.stop();
  }
}

// ---------------------------------------------------------------------------
// 2. ANSI -> HTML (only the SGR codes src/cli/output.ts and demo/run.mjs use)

const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
// eslint-disable-next-line no-control-regex
const SGR = /\u001b\[([\d;]*)m/g;
const plain = (s) => s.replace(SGR, '');

/** Convert one line with ANSI colours to HTML, truncated to `max` visible characters. */
function ansiLine(line, max = 104) {
  let bold = false;
  let dim = false;
  let fg = '';
  let html = '';
  let visible = 0;
  let last = 0;
  const emit = (text) => {
    if (!text || visible >= max) return;
    let t = text;
    if (visible + t.length > max) t = `${t.slice(0, max - visible - 1)}…`;
    visible += t.length;
    const cls = [bold ? 'b' : '', dim ? 'd' : '', fg ? `c${fg}` : ''].filter(Boolean).join(' ');
    html += cls ? `<span class="${cls}">${esc(t)}</span>` : esc(t);
  };
  for (const m of line.matchAll(SGR)) {
    emit(line.slice(last, m.index));
    last = m.index + m[0].length;
    for (const code of (m[1] || '0').split(';').map(Number)) {
      if (code === 0) [bold, dim, fg] = [false, false, ''];
      else if (code === 1) bold = true;
      else if (code === 2) dim = true;
      else if (code === 22) [bold, dim] = [false, false];
      else if (code === 39) fg = '';
      else if ((code >= 30 && code <= 37) || code === 90) fg = String(code);
    }
  }
  emit(line.slice(last));
  return html;
}

/** Squeeze runs of padding in table rows so the interesting columns fit the GIF width. */
const squeeze = (line) => line.replace(/ {3,}/g, '  ');

function curate({ first, baseline, attack }) {
  const lines = (s) => s.replace(/\r/g, '').split('\n');
  const upTo = (arr, pred) => arr.slice(0, arr.findIndex(pred) + 1);

  const scan1 = upTo(lines(first.stdout), (l) => plain(l).trim().startsWith('Outbound domains')).map(squeeze);
  const base = lines(baseline.stdout).filter((l) => /^(acme-outfitters: create|\s+\d+ approved|Saved )/.test(plain(l)));

  const att = lines(attack.stdout);
  const tableAt = att.findIndex((l) => plain(l).trim().startsWith('TYPE'));
  const tableEnd = att.findIndex((l, i) => i > tableAt && plain(l).trim() === '');
  const table = att.slice(tableAt, tableEnd).map(squeeze);
  const summaryAt = att.findIndex((l) => plain(l).startsWith('Summary:'));
  // Keep severity + title; the confidence and finding ID are in the report.
  const findings = att
    .filter((l) => /^(CRITICAL|HIGH|MEDIUM|LOW) /.test(plain(l)))
    // eslint-disable-next-line no-control-regex
    .map((l) => l.replace(/ (?:\u001b\[90m)?confidence \w+(?:\u001b\[39m)?/, '').replace(/ (?:\u001b\[90m)?TS-[0-9a-f]{12}.*$/, ''));
  const scan2 = [...table, '', att[summaryAt], att[summaryAt + 1], '', `\u001b[1mFindings (${findings.length})\u001b[22m`, ...findings];
  return { scan1, base, scan2, exitCode: attack.code };
}

// ---------------------------------------------------------------------------
// 3. Play it back and record frames

async function record(curated, reportPath) {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: WIDTH, height: HEIGHT }, deviceScaleFactor: 1 });
  await page.goto(pathToFileURL(join(ROOT, 'scripts', 'demo', 'stage.html')).href);
  const frames = [];
  const snap = async (delay) => frames.push({ png: await page.screenshot({ type: 'png' }), delay });
  const st = (fn, ...a) => page.evaluate(([f, args]) => window.stage[f](...args), [fn, a]);

  async function typeCommand(cmd) {
    await st('startTyping');
    await snap(500);
    for (let i = 2; i <= cmd.length + 1; i += 2) {
      await st('type', esc(cmd.slice(0, i)));
      await snap(45);
    }
    await snap(350);
    await st('commit');
  }
  async function reveal(lines, perFrame = 2, delay = 70) {
    for (let i = 0; i < lines.length; i += perFrame) {
      await st('add', lines.slice(i, i + perFrame).map((l) => ansiLine(l)));
      await snap(delay);
    }
  }

  await st('add', [ansiLine('\u001b[90m# Acme Outfitters: approve the checkout as it is today\u001b[39m')]);
  await typeCommand('npx thirdsentry scan');
  await reveal(curated.scan1, 2, 80);
  await snap(1600);
  await typeCommand('npx thirdsentry baseline --yes');
  await reveal(curated.base, 1, 120);
  await st('prompt');
  await snap(1500);

  await st(
    'caption',
    `<h2>⚠ Later: the payment vendor's CDN is compromised</h2><ul>
<li>a card skimmer is appended to <code>pay.js</code></li>
<li>an obfuscated "jquery" loader appears from <code>cdn-assets-cloud.test</code></li>
<li>card data is beaconed to <code>collect.exfil.test</code></li>
<li>the checkout form now posts to the attacker and asks for a PIN</li>
<li>CSP and X-Frame-Options are dropped from <code>/checkout</code></li></ul>`,
  );
  await snap(4200);
  await st('caption', null);
  await st('clear');
  await st('add', [ansiLine('\u001b[90m# the scheduled scan runs again (cron or CI)\u001b[39m')]);
  await typeCommand('npx thirdsentry scan --fail-on high');
  await reveal(curated.scan2.slice(0, 6), 2, 90);
  await reveal(curated.scan2.slice(6), 1, 160);
  await snap(1400);
  await typeCommand('echo $?');
  await st('add', [ansiLine(`\u001b[1;31m${curated.exitCode}\u001b[0m  \u001b[90m← the CI job fails and the alert goes out\u001b[39m`)]);
  await st('prompt');
  await snap(2600);

  await st('showBrowser', pathToFileURL(reportPath).href);
  await page.waitForTimeout(300);
  await snap(2800);
  // The iframe is cross-origin (file://), so scroll by moving it rather than through its window.
  for (let y = 80; y <= 800; y += 80) {
    await st('scrollReport', y);
    await snap(60);
  }
  await snap(3800);
  await browser.close();
  return frames;
}

// ---------------------------------------------------------------------------
// 4. Encode: unchanged pixels become transparent so each frame stores only the diff

function encode(frames) {
  const gif = GIFEncoder();
  let prev;
  for (const [i, f] of frames.entries()) {
    const { data, width, height } = PNG.sync.read(f.png);
    const rgba = new Uint8Array(data.buffer, data.byteOffset, data.length);
    const palette = quantize(rgba, 255, { format: 'rgb565' });
    const index = applyPalette(rgba, palette, 'rgb565');
    if (prev) {
      const transparentIndex = palette.length;
      palette.push([255, 0, 255]);
      for (let p = 0; p < index.length; p++) {
        const o = p * 4;
        if (rgba[o] === prev[o] && rgba[o + 1] === prev[o + 1] && rgba[o + 2] === prev[o + 2]) index[p] = transparentIndex;
      }
      gif.writeFrame(index, width, height, { palette, delay: f.delay, transparent: true, transparentIndex, dispose: 1 });
    } else {
      gif.writeFrame(index, width, height, { palette, delay: f.delay, repeat: 0 });
    }
    prev = rgba;
    if (i % 25 === 0) log(`  encoded ${i}/${frames.length} frames`);
  }
  gif.finish();
  return Buffer.from(gif.bytes());
}

// ---------------------------------------------------------------------------

async function screenshotReport(reportPath, out) {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1000, height: 1080 }, deviceScaleFactor: 1.5 });
  await page.goto(pathToFileURL(reportPath).href);
  await page.screenshot({ path: out });
  await browser.close();
}

async function main() {
  await mkdir(ASSETS, { recursive: true });
  const run = await runScenario();
  const curated = curate(run);

  const html = stripWork(await readFile(run.reportPath, 'utf8'));
  await writeFile(join(ASSETS, 'sample-report.html'), html);
  log('wrote docs/assets/sample-report.html');

  await screenshotReport(run.reportPath, join(ASSETS, 'report-screenshot.png'));
  log('wrote docs/assets/report-screenshot.png');

  log('recording frames...');
  const frames = await record(curated, run.reportPath);
  if (process.env.DEMO_FRAMES_DIR) {
    // Debugging aid: save the long-held "key" frames as PNGs to eyeball the GIF without a viewer.
    await mkdir(process.env.DEMO_FRAMES_DIR, { recursive: true });
    const keys = frames.filter((f) => f.delay >= 1000);
    await Promise.all(keys.map((f, i) => writeFile(join(process.env.DEMO_FRAMES_DIR, `key-${String(i).padStart(2, '0')}.png`), f.png)));
  }
  const gif = encode(frames);
  await writeFile(join(ASSETS, 'demo.gif'), gif);
  const seconds = frames.reduce((s, f) => s + f.delay, 0) / 1000;
  log(`wrote docs/assets/demo.gif (${frames.length} frames, ${seconds.toFixed(1)} s, ${(gif.length / 1024 / 1024).toFixed(2)} MB)`);

  await rm(WORK, { recursive: true, force: true });
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
  process.exit(1);
});
