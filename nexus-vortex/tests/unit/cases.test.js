const test = require('node:test');
const assert = require('node:assert/strict');
const { Core, Rules, Cases, ingestDir } = require('./helpers.js');

function suspiciousCase() {
  const { records, receipts } = ingestDir('suspicious');
  const finding = Rules.evaluate(records).findings.find(f => f.ruleId === 'NV-AUTH-002');
  const byId = new Map(records.map(r => [r.id, r]));
  const c = Cases.createCase({ finding, records: finding.evidenceIds.map(id => byId.get(id)), sources: receipts.map(r => ({ ...r, fileSha256: 'f'.repeat(64) })) });
  Cases.addNote(c, 'Owner of deploy says they did not log in.');
  Cases.setDisposition(c, { status: 'investigating', disposition: 'true-positive', note: 'Confirmed with owner.' });
  return { c, finding };
}

test('a case from a finding snapshots the rule, evidence, digests and sources', () => {
  const { c, finding } = suspiciousCase();
  assert.equal(c.schema, 2);
  assert.equal(c.findings[0].ruleVersion, finding.ruleVersion);
  assert.equal(c.evidence.length, finding.evidenceIds.length);
  assert.ok(c.evidence.every(e => e.raw && e.rawSha256 === Core.sha256Text(e.raw)));
  assert.deepEqual(c.sources.map(s => s.fileName), ['auth.log']);
  assert.deepEqual(c.history.map(h => h.action), ['created', 'evidence-attached', 'note-added', 'disposition']);
  assert.throws(() => Cases.setDisposition(c, { disposition: 'pwned' }), /Unknown disposition/);
});

test('exported case verifies after round trip', () => {
  const { c } = suspiciousCase();
  const exp = Cases.buildExport(c, { includeRaw: true, app: { version: 'test' } });
  const v = Cases.verifyExport(exp.text);
  assert.equal(v.ok, true, JSON.stringify(v.report.errors));
  assert.equal(v.report.content, 'match');
  assert.equal(v.report.evidence.matched, c.evidence.length);
  assert.equal(v.report.fileSha256, exp.fileSha256);
  assert.deepEqual(v.case, JSON.parse(JSON.stringify(c)));
});

test('tampering is detected; re-computed digests are not (and the notice says so)', () => {
  const { c } = suspiciousCase();
  const doc = JSON.parse(Cases.buildExport(c).text);
  const edited = JSON.parse(JSON.stringify(doc));
  edited.case.evidence[0].raw = edited.case.evidence[0].raw.replace('203.0.113.45', '192.0.2.200');
  let v = Cases.verifyExport(JSON.stringify(edited));
  assert.equal(v.ok, false);
  assert.equal(v.report.content, 'mismatch');
  assert.deepEqual(v.report.evidence.mismatched, [c.evidence[0].id]);

  const notes = JSON.parse(JSON.stringify(doc));
  notes.case.disposition = 'false-positive';
  v = Cases.verifyExport(JSON.stringify(notes));
  assert.equal(v.report.content, 'mismatch');
  assert.equal(v.report.evidence.mismatched.length, 0, 'raw lines unchanged');

  const forged = JSON.parse(JSON.stringify(edited));
  forged.case.evidence[0].rawSha256 = Core.sha256Text(forged.case.evidence[0].raw);
  const { integrity, notice, ...body } = forged;
  forged.integrity.contentSha256 = Core.sha256Text(Core.canonicalJSON(body));
  v = Cases.verifyExport(JSON.stringify(forged));
  assert.equal(v.ok, true, 'a forger who recomputes every digest passes verification');
  assert.notEqual(v.report.fileSha256, Cases.buildExport(c).fileSha256, 'only an out-of-band file digest reveals it');
  assert.match(Cases.NOTICE, /do not prove who created/);
  void integrity; void notice;
});

test('redacted export keeps digests, marks raw as unverifiable and still matches content', () => {
  const { c } = suspiciousCase();
  const exp = Cases.buildExport(c, { includeRaw: false });
  const evidence = JSON.parse(exp.text).case.evidence;
  assert.ok(evidence.every(e => e.raw === null && e.rawRedacted === true && /^[0-9a-f]{64}$/.test(e.rawSha256)));
  assert.ok(evidence.some(e => /Failed password/.test(e.message)), 'normalised summaries remain, so the export dialog must not call this anonymised');
  const v = Cases.verifyExport(exp.text);
  assert.equal(v.report.content, 'match');
  assert.equal(v.report.evidence.unverifiable.length, c.evidence.length);
  assert.ok(v.report.warnings.some(w => /without raw evidence/.test(w)));
});

test('verification rejects foreign and malformed files with a reason', () => {
  assert.match(Cases.verifyExport('{not json').report.errors[0], /not valid JSON/);
  assert.match(Cases.verifyExport('{"format":"other"}').report.errors[0], /Not a NEXUS VORTEX case export/);
  const { c } = suspiciousCase();
  const doc = JSON.parse(Cases.buildExport(c).text);
  doc.case.schema = 99;
  assert.match(Cases.verifyExport(JSON.stringify(doc)).report.errors.join(' '), /Unsupported case schema 99/);
});

test('v1 Security Fabric investigations migrate without losing notes or evidence', () => {
  const v1 = { id: 'abc', title: 'Old case', notes: 'note text', status: 'resolved', updated: '2026-10-01T00:00:00.000Z', created: '2026-09-30T00:00:00.000Z', rule: 'AUTH-BURST-5', assetKey: '192.0.2.5',
    evidence: [{ id: 7, time: '2026-09-30T10:00:00.000Z', received: '2026-09-30T10:00:01.000Z', source: 'auth.log', origin: 'IMPORT', severity: 'medium', type: 'text/syslog', src: '192.0.2.5', dst: '', port: '', host: '', message: 'Failed password', raw: 'Sep 30 10:00:00 h sshd[1]: Failed password', fields: {} }] };
  const c = Cases.normalizeCase(v1);
  assert.equal(c.schema, 2);
  assert.equal(c.status, 'closed');
  assert.equal(c.notes[0].text, 'note text');
  assert.equal(c.evidence[0].raw, v1.evidence[0].raw);
  assert.equal(c.evidence[0].rawSha256, Core.sha256Text(v1.evidence[0].raw));
  assert.equal(c.evidence[0].timeQuality, 'migrated');
  assert.equal(c.history[0].action, 'migrated');
  assert.ok(Cases.verifyExport(Cases.buildExport(c).text).ok);
});

test('limits raise errors instead of trimming evidence', () => {
  const { c } = suspiciousCase();
  const many = Array.from({ length: Cases.LIMITS.evidence }, (_, i) => ({ id: 'x' + i, raw: 'r', rawSha256: Core.sha256Text('r') }));
  assert.throws(() => Cases.attachEvidence(c, many), /at most 2,000/);
  assert.equal(c.evidence.length, 13, 'nothing was attached');
});

test('sensitivity report counts identities and credential-like content', () => {
  const { c } = suspiciousCase();
  Cases.addNote(c, 'temporary password: hunter2hunter2hunter2');
  const s = Cases.sensitivity(c, text => /password:\s*\S{12,}/.test(text) ? ['possible credential assignment'] : []);
  assert.equal(s.rawCount, c.evidence.length);
  assert.ok(s.accountCount >= 5);
  assert.deepEqual(s.hosts, ['web-01']);
  assert.equal(s.credentialHits.length, 1);
});
