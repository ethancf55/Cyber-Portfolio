import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { chromium } from 'playwright-core';

const PUBLIC = new URL('../../dist/public/index.html', import.meta.url);
const LOCAL = new URL('../../dist/local/index.html', import.meta.url);
const SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

let server, port, browser;
const origin = () => 'http://127.0.0.1:' + port + '/';

before(async () => {
  const html = readFileSync(PUBLIC, 'utf8');
  server = createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); res.end(html); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  port = server.address().port;
  browser = await chromium.launch({ executablePath: '/usr/local/bin/google-chrome', args: ['--no-sandbox'] });
});
after(async () => { await browser?.close(); await new Promise(resolve => server.close(resolve)); });

async function open(hash = '#/investigate') {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto(origin() + hash);
  await page.keyboard.press('Escape');
  await page.waitForFunction(() => window.NEXUS_VORTEX?.investigation?.Ingest.mode);
  return { page, errors };
}
async function loadFixture(page, name) {
  if (await page.locator('.ir-synthetic:not([open]) summary').count()) await page.locator('.ir-synthetic summary').click();
  const mark = await page.evaluate(() => Date.now());
  await page.locator(`[data-ir-fixture="${name}"]`).click();
  await page.waitForFunction(({ n, mark }) => {
    const inv = window.NEXUS_VORTEX?.investigation;
    if (!inv || inv.Ingest.current || inv.Ingest.queued) return false;
    const mine = [...inv.Ingest.imports.values()].filter(e => String(e.fileName).startsWith('synthetic/' + n + '/') && e.startedAt >= mark);
    return mine.length > 0 && mine.every(e => e.status !== 'running') && inv.Investigation.st.rulesAt >= mark;
  }, { n: name, mark }, { timeout: 30000 });
}
async function clearEvidence(page) {
  await page.locator('#irClearAll').click();
  await page.locator('#confirmOk').click();
  await page.waitForFunction(() => document.body.dataset && (window.NEXUS_VORTEX.investigation.Evidence.count === 0));
}

test('public edition keeps companion controls disabled and local edition does not ship that lock', () => {
  const pub = readFileSync(PUBLIC, 'utf8'), loc = readFileSync(LOCAL, 'utf8');
  assert.match(pub, /LOCAL COMPANION REQUIRED/);
  assert.doesNotMatch(loc, /LOCAL COMPANION REQUIRED/);
  assert.match(loc, /LOCAL EDITION/);
});

test('suspicious evidence becomes an explainable finding, a mesh selection, a timeline and a case that survives reload', async () => {
  const { page, errors } = await open();
  await loadFixture(page, 'suspicious');
  await page.waitForFunction(() => /13 failures/.test(document.querySelector('#irFindingList')?.textContent || ''));
  const titles = await page.locator('#irFindingList .ir-finding strong').allTextContents();
  assert.ok(titles.some(t => /13 failures/.test(t)), titles.join(' | '));
  assert.ok(titles.some(t => /Regular 60 s/.test(t)));
  assert.ok(titles.some(t => /NXDOMAIN/.test(t)));

  await page.locator('#irFindingList .ir-finding', { hasText: '13 failures' }).click();
  await page.waitForSelector('#irDetailBody .ir-triad');
  const dossier = await page.locator('#irDetailBody').innerText();
  assert.match(dossier, /NV-AUTH-002 v1\.0\.0/);
  assert.match(dossier, /SEVERITY\s+HIGH/);
  assert.match(dossier, /EVIDENCE COMPLETENESS\s+PARTIAL/);
  assert.match(dossier, /CONFIDENCE \(IN THE INTERPRETATION\)\s+MODERATE/);
  assert.match(dossier, /auth\.log/);
  assert.match(dossier, /Alternative explanations/i);
  assert.match(dossier, /What remains unknown/i);
  assert.equal(await page.locator('#irDetailBody img, #irDetailBody script').count(), 0);

  await page.waitForFunction(() => {
    const c = document.querySelector('#irMeshCanvas'); if (!c) return false;
    const d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data;
    let n = 0; for (let i = 3; i < d.length; i += 80) if (d[i] > 8) n++;
    return n > 100;
  });
  await page.locator('[data-ir-case-from]').click();
  await page.waitForSelector('#irCaseTitle');
  const caseId = await page.evaluate(() => window.NEXUS_VORTEX.investigation.CaseStore.list()[0].id);
  assert.equal(await page.evaluate(id => window.NEXUS_VORTEX.investigation.CaseStore.get(id).evidence.length, caseId), 13);

  await page.reload();
  await page.keyboard.press('Escape');
  await page.waitForFunction(id => window.NEXUS_VORTEX?.investigation?.CaseStore.list().some(c => c.id === id), caseId);
  await page.locator(`[data-ir-case="${caseId}"]`).click();
  assert.match(await page.locator('#irCaseEditor').innerText(), /13/);
  await page.locator('[data-ir-case-restore]').click();
  await page.waitForFunction(() => window.NEXUS_VORTEX.investigation.Evidence.count >= 13 && window.NEXUS_VORTEX.investigation.Investigation.st.findings.length >= 1);
  await page.evaluate(() => {
    const inv = window.NEXUS_VORTEX.investigation;
    inv.Investigation.selectFinding(inv.Investigation.st.findings[0].id);
  });
  await page.locator('#irDetailBody [data-ir-asset]').first().click();
  await page.waitForFunction(() => document.querySelector('#irDetailKicker')?.textContent === 'ASSET');
  assert.match(await page.locator('#irDetailBody').innerText(), /RELATIONSHIPS/);

  await page.locator('[data-ir-case-export]').click();
  await page.locator('#irExportAck').check();
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.locator('#irExportGo').click()
  ]);
  const path = await download.path();
  const text = readFileSync(path, 'utf8');
  const fileSha = await page.locator('[data-ir-export-sha]').innerText();
  assert.match(fileSha, /^[0-9a-f]{64}$/);
  const fresh = await browser.newPage();
  fresh.on('pageerror', e => errors.push(e.message));
  await fresh.goto(origin() + '#/investigate');
  await fresh.keyboard.press('Escape');
  await fresh.waitForSelector('#irCaseFile', { state: 'attached' });
  await fresh.setInputFiles('#irCaseFile', { name: 'case.json', mimeType: 'application/json', buffer: Buffer.from(text) });
  await fresh.waitForSelector('.ir-verify');
  assert.match(await fresh.locator('.ir-verify').innerText(), /VERIFIED/);
  const shown = await fresh.locator('[data-ir-verify-sha]').innerText();
  assert.equal(shown, fileSha, 're-import reports the same file digest');
  await fresh.locator('[data-ir-import-save]').first().click();
  await fresh.waitForFunction(() => window.NEXUS_VORTEX.investigation.CaseStore.list().some(c => c.importVerification?.ok));
  await fresh.close();
  assert.deepEqual(errors, []);
  await page.close();
});

test('benign fixture stays quiet, malformed fixture explains itself, hostile text stays text, timestamps stay distinct', async () => {
  const { page, errors } = await open();
  await loadFixture(page, 'benign');
  await page.waitForFunction(() => document.querySelector('#irCoverageBody')?.textContent.includes('NV-NET-001'));
  assert.match(await page.locator('#irFindingCount').innerText(), /^0/);
  assert.match(await page.locator('#irCoverageBody').evaluate(el => el.textContent), /NV-NET-001[\s\S]*evaluated/i);

  await clearEvidence(page);
  await loadFixture(page, 'malformed');
  await page.locator('[data-ir-receipt]').first().click();
  const receipts = await page.locator('#irReceiptDetail').innerText();
  assert.match(receipts, /Rejected|NOT RECOGNISED|Invalid JSON|missing required column|Unbalanced|not a text log/i);

  await clearEvidence(page);
  await loadFixture(page, 'hostile');
  assert.equal(await page.locator('#view-investigate img, #view-investigate script').count(), 0);
  await page.locator('#irQuery').fill('<script>alert');
  await page.waitForTimeout(250);
  const cell = page.locator('#irRows').getByText('<script>alert', { exact: false });
  assert.ok(await cell.count() > 0);
  assert.equal(await page.locator('#irRows script, #irRows img, #irRows iframe').count(), 0);

  await clearEvidence(page);
  await loadFixture(page, 'timestamps');
  await page.locator('[data-ir-receipt]', { hasText: 'idp-signins.csv' }).click();
  const quality = await page.locator('#irReceiptDetail').innerText();
  assert.match(quality, /AMBIGUOUS/);
  assert.match(quality, /ASSUMED/);
  assert.match(quality, /differ/);
  assert.deepEqual(errors, []);
  await page.close();
});

test('a large import can be cancelled and a storage failure stays visible', async () => {
  const { page, errors } = await open();
  await page.evaluate(() => {
    window.__NV_IMPORT_PACE = 50;
    window.NEXUS_VORTEX.investigation.Ingest.on(what => { if (what === 'progress') window.NEXUS_VORTEX.investigation.Ingest.cancel(); });
  });
  if (await page.locator('.ir-synthetic:not([open]) summary').count()) await page.locator('.ir-synthetic summary').click();
  await page.locator('[data-ir-fixture="large"]').click();
  await page.waitForFunction(() => {
    const entry = [...window.NEXUS_VORTEX.investigation.Ingest.imports.values()].find(e => /large-50000/.test(e.fileName));
    if (!entry || entry.status === 'running') return false;
    if (entry.status !== 'cancelled') throw new Error('status ' + entry.status);
    return /CANCELLED/.test(document.querySelector('#irReceiptDetail')?.textContent || '');
  }, null, { timeout: 30000 });
  const detail = await page.locator('#irReceiptDetail').innerText();
  assert.match(detail, /CANCELLED/);
  assert.match(detail, /removed|rolled back/i);
  assert.equal(await page.evaluate(() => window.NEXUS_VORTEX.investigation.Evidence.count), 0);

  await loadFixture(page, 'benign');
  await page.evaluate(() => new Promise((resolve, reject) => {
    const req = indexedDB.open('nexus-vortex-cases', 99);
    req.onsuccess = () => { req.result.close(); resolve(); };
    req.onerror = () => reject(req.error);
  }));
  await page.locator('#irNewCase').click();
  await page.waitForFunction(() => /NOT SAVED|storage|unavailable|closed/i.test(document.querySelector('#irCaseSave')?.textContent || document.querySelector('#irStoreStatus')?.textContent || ''));
  assert.match((await page.locator('#irCaseSave').innerText()) + (await page.locator('#irStoreStatus').innerText()), /NOT SAVED|storage|unavailable|closed/i);
  assert.deepEqual(errors, []);
  await page.close();
});

test('hashing and route changes keep working', async () => {
  const { page, errors } = await open('#/defense');
  const digest = await page.evaluate(async () => {
    const file = new File(['abc'], 'sample.txt');
    const out = await window.NEXUS_VORTEX.defense.hashFile(file, ['SHA-256']);
    return out['SHA-256'];
  });
  assert.equal(digest, SHA256_ABC);
  for (const route of ['command', 'mesh', 'operations', 'lab', 'investigate']) {
    await page.locator(`.navbtn[data-route="${route}"]`).click();
    await page.waitForSelector(`#view-${route}.is-active`);
  }
  assert.equal(await page.locator('#opScan').isDisabled(), true);
  assert.deepEqual(errors, []);
  await page.close();
});
