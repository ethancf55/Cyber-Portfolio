/* Measure a 50,000-event import in headless Chrome and write the numbers. */
import { createServer } from 'node:http';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { chromium } from 'playwright-core';
import { cpus, totalmem } from 'node:os';

const html = readFileSync(new URL('../../dist/public/index.html', import.meta.url), 'utf8');
const server = createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); res.end(html); });
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;
const browser = await chromium.launch({ executablePath: '/usr/local/bin/google-chrome', args: ['--no-sandbox', '--enable-precise-memory-info'] });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const errors = [];
page.on('pageerror', e => errors.push(e.message));
await page.goto('http://127.0.0.1:' + port + '/#/investigate');
await page.keyboard.press('Escape');
await page.waitForSelector('#irEngineChip');
if (await page.locator('.ir-synthetic:not([open]) summary').count()) await page.locator('.ir-synthetic summary').click();
const wallStart = Date.now();
await page.locator('[data-ir-fixture="large"]').click();
await page.waitForFunction(() => {
  const inv = window.NEXUS_VORTEX?.investigation;
  if (!inv || inv.Ingest.current || inv.Ingest.queued) return false;
  const entry = [...inv.Ingest.imports.values()].find(e => /large-50000/.test(e.fileName));
  return entry && entry.status !== 'running' && inv.Investigation.st.rulesAt >= entry.startedAt;
}, null, { timeout: 120000 });
const wallMs = Date.now() - wallStart;
const report = await page.evaluate(() => {
  const inv = window.NEXUS_VORTEX.investigation;
  const entry = [...inv.Ingest.imports.values()].find(e => /large-50000/.test(e.fileName));
  const mem = performance.memory;
  return {
    engine: document.querySelector('#irEngineChip')?.textContent || '',
    records: inv.Evidence.count,
    rawChars: inv.Evidence.rawChars,
    status: entry.status,
    accepted: entry.receipt?.accepted,
    rejected: entry.receipt?.rejected,
    duplicates: entry.receipt?.duplicates,
    importMs: entry.receipt?.durationMs,
    rulesMs: inv.Investigation.st.rulesMs,
    rulesRecords: inv.Investigation.st.rulesRecords,
    findings: inv.Investigation.st.findings.length,
    heapUsed: mem ? mem.usedJSHeapSize : null,
    heapTotal: mem ? mem.totalJSHeapSize : null
  };
});
const nav = await page.evaluate(async () => {
  const t = performance.now();
  await window.NEXUS_VORTEX.router.go('mesh');
  const mesh = performance.now() - t;
  const t2 = performance.now();
  await window.NEXUS_VORTEX.router.go('investigate');
  return { toMeshMs: Math.round(mesh), backMs: Math.round(performance.now() - t2) };
});
const out = {
  measuredAt: new Date().toISOString(),
  environment: { runtime: 'Google Chrome headless via Playwright', node: process.version, cpus: cpus().length, cpuModel: cpus()[0]?.model, memoryBytes: totalmem(), viewport: '1440x900' },
  workload: '50,000 synthetic Suricata EVE JSON events, one file, generated in the page, parsed in the ingest worker, rules over the whole set',
  wallClockMs: wallMs,
  navigation: nav,
  pageErrors: errors,
  ...report
};
mkdirSync(new URL('../../', import.meta.url), { recursive: true });
writeFileSync('/opt/cursor/artifacts/perf-50000.json', JSON.stringify(out, null, 2));
console.log(JSON.stringify(out, null, 2));
await browser.close();
await new Promise(resolve => server.close(resolve));
if (errors.length || report.status !== 'complete' || report.records < 50000) process.exit(1);
