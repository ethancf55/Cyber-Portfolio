const test = require('node:test');
const assert = require('node:assert/strict');
const { Rules, ingestDir, ingest } = require('./helpers.js');

const T = Date.UTC(2026, 9, 23, 18, 0, 0);
const iso = ms => new Date(ms).toISOString();
const syslogAt = ms => { const d = new Date(ms); return ['Oct', String(d.getUTCDate()).padStart(2, ' '), d.toISOString().slice(11, 19)].join(' '); };
const auth = rows => ingest(rows.join('\n'), { fileName: 'auth.log', format: 'syslog-auth', options: { now: Date.UTC(2026, 10, 2), syslogYear: 2026 } }).records;
const conn = times => ingest(times.map((t, i) => JSON.stringify({ timestamp: iso(t), event_type: 'flow', src_ip: '10.0.0.5', src_port: 40000 + i, dest_ip: '198.51.100.9', dest_port: 443, proto: 'TCP', flow: { start: iso(t) } })).join('\n'), { fileName: 'eve.json' }).records;

test('benign fixture produces no findings and every rule reports its coverage', () => {
  const { records } = ingestDir('benign');
  const out = Rules.evaluate(records);
  assert.deepEqual(out.findings, []);
  const cov = Object.fromEntries(out.coverage.map(c => [c.ruleId, c]));
  assert.equal(cov['NV-AUTH-002'].status, 'evaluated');
  assert.equal(cov['NV-NET-001'].status, 'evaluated');
  assert.equal(cov['NV-NET-001'].excluded['excluded port (DNS/NTP/mDNS)'], 40, 'the 64 s NTP series is excluded by port, not by luck');
  assert.equal(cov['NV-SRC-001'].status, 'not-applicable');
});

test('suspicious fixture: each finding cites exactly its supporting records', () => {
  const { records } = ingestDir('suspicious');
  const byId = new Map(records.map(r => [r.id, r]));
  const out = Rules.evaluate(records);
  const rules = out.findings.map(f => f.ruleId).sort();
  assert.deepEqual(rules, ['NV-AUTH-002', 'NV-DNS-001', 'NV-NET-001', 'NV-SRC-001', 'NV-SRC-001']);

  const a = out.findings.find(f => f.ruleId === 'NV-AUTH-002');
  const ev = a.evidenceIds.map(id => byId.get(id));
  assert.ok(ev.every(r => r.src === '203.0.113.45'));
  assert.equal(ev.filter(r => r.outcome === 'success').length, 1);
  assert.equal(ev.find(r => r.outcome === 'success').user, 'deploy');
  assert.ok(!ev.some(r => r.outcome === 'notice'), '"Invalid user" notices are not counted as failures');
  assert.equal(a.thresholds[0].observed, 13, '11 failure lines, one of them "message repeated 2 times"');
  assert.equal(a.completeness, 'partial', 'syslog year/zone were assumed');
  assert.ok(a.completenessNotes.some(n => /assumption/.test(n)));
  assert.equal(a.severity, 'high');
  assert.equal(a.confidence, 'moderate');
  assert.ok(a.alternatives.length >= 3 && a.missingContext.length >= 3);

  const n = out.findings.find(f => f.ruleId === 'NV-NET-001');
  const conns = n.evidenceIds.map(id => byId.get(id));
  assert.ok(conns.every(r => r.kind === 'conn' && r.dst === '198.51.100.77' && r.port === 443));
  assert.equal(conns.length, 46);
  assert.match(n.thresholds[1].observed, /^(59|60)\.\d\d s$/);
  assert.ok(n.corroboration.length > 0, 'destination also appears in the DNS and alert findings');

  const d = out.findings.find(f => f.ruleId === 'NV-DNS-001');
  const dns = d.evidenceIds.map(id => byId.get(id));
  assert.equal(dns.filter(r => r.rcode === 'NXDOMAIN').length, 15);
  assert.ok(dns.some(r => r.query === 'update-cdn.example' && r.answers.includes('198.51.100.77')));
  const inferred = d.edges.filter(e => e.kind === 'inferred');
  assert.equal(inferred.length, 1);
  assert.match(inferred[0].basis, /^Inferred:/);
});

test('AUTH-002 threshold boundary: 4 failures then success is not reported, 5 is', () => {
  const rows = k => [...Array.from({ length: k }, (_, i) => `${syslogAt(T + i * 10000)} h sshd[1]: Failed password for bob from 192.0.2.5 port ${1000 + i} ssh2`), `${syslogAt(T + 60000)} h sshd[1]: Accepted password for bob from 192.0.2.5 port 2000 ssh2`];
  assert.equal(Rules.evaluate(auth(rows(4))).findings.length, 0);
  const five = Rules.evaluate(auth(rows(5))).findings;
  assert.equal(five.length, 1);
  assert.equal(five[0].confidence, 'low', 'single account, few failures: consistent with mistyping');
});

test('AUTH-002 lookback: failures older than 10 minutes before the success do not count', () => {
  const rows = [...Array.from({ length: 6 }, (_, i) => `${syslogAt(T + i * 1000)} h sshd[1]: Failed password for bob from 192.0.2.5 port ${1000 + i} ssh2`), `${syslogAt(T + 11 * 60000)} h sshd[1]: Accepted password for bob from 192.0.2.5 port 2000 ssh2`];
  const out = Rules.evaluate(auth(rows));
  assert.deepEqual(out.findings.map(f => f.ruleId), ['NV-AUTH-001'], 'reported as a failure burst instead');
});

test('PAM and service lines for the same attempts are not double counted', () => {
  const rows = [];
  for (let i = 0; i < 3; i++) {
    rows.push(`${syslogAt(T + i * 5000)} h sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.5  user=bob`);
    rows.push(`${syslogAt(T + i * 5000 + 200)} h sshd[1]: Failed password for bob from 192.0.2.5 port ${1000 + i} ssh2`);
  }
  rows.push(`${syslogAt(T + 30000)} h sshd[1]: Accepted password for bob from 192.0.2.5 port 2000 ssh2`);
  assert.equal(Rules.evaluate(auth(rows)).findings.length, 0, '3 attempts, logged twice each, stay below the threshold of 5');
});

test('NET-001: minimum count, regularity and exclusions', () => {
  const periodic = n => Array.from({ length: n }, (_, i) => T + i * 60000 + (i % 2 ? 700 : -700));
  assert.equal(Rules.evaluate(conn(periodic(7))).findings.length, 0, '7 connections is below the minimum of 8');
  assert.equal(Rules.evaluate(conn(periodic(8))).findings.length, 1);
  let x = T; const irregular = Array.from({ length: 40 }, (_, i) => (x += [5000, 90000, 31000, 240000, 12000][i % 5]));
  const out = Rules.evaluate(conn(irregular));
  assert.equal(out.findings.length, 0);
  assert.match(out.coverage.find(c => c.ruleId === 'NV-NET-001').detail, /1 were not regular enough/);
  const external = ingest(periodic(12).map((t, i) => JSON.stringify({ timestamp: iso(t), event_type: 'flow', src_ip: '192.0.2.8', src_port: i + 1, dest_ip: '198.51.100.9', dest_port: 443, flow: { start: iso(t) } })).join('\n')).records;
  const ext = Rules.evaluate(external);
  assert.equal(ext.findings.length, 0);
  assert.equal(ext.coverage.find(c => c.ruleId === 'NV-NET-001').status, 'insufficient', 'without internal sources, direction cannot be established');
});

test('DNS-001 reports insufficient evidence for query-only DNS logging', () => {
  const q = Array.from({ length: 20 }, (_, i) => JSON.stringify({ timestamp: iso(T + i * 1000), event_type: 'dns', src_ip: '10.0.0.5', dest_ip: '10.0.0.2', dns: { type: 'query', rrname: 'n' + i + '.test', rrtype: 'A' } })).join('\n');
  const cov = Rules.evaluate(ingest(q).records).coverage.find(c => c.ruleId === 'NV-DNS-001');
  assert.equal(cov.status, 'insufficient');
  assert.match(cov.detail, /query-only/);
});

test('records without usable timestamps are excluded from time rules and counted', () => {
  const rows = Array.from({ length: 8 }, (_, i) => JSON.stringify({ event_type: 'flow', src_ip: '10.0.0.5', src_port: i, dest_ip: '198.51.100.9', dest_port: 443, flow: {} })).join('\n');
  const cov = Rules.evaluate(ingest(rows).records).coverage.find(c => c.ruleId === 'NV-NET-001');
  assert.equal(cov.excluded['no usable timestamp'], 8);
});

test('evaluation is deterministic and independent of input order', () => {
  const { records } = ingestDir('suspicious');
  const a = Rules.evaluate(records).findings.map(f => [f.id, f.evidenceIds.slice().sort().join()]);
  const shuffled = records.slice().sort((x, y) => (x.rawSha256 < y.rawSha256 ? -1 : 1));
  const b = Rules.evaluate(shuffled).findings.map(f => [f.id, f.evidenceIds.slice().sort().join()]);
  assert.deepEqual(b.sort(), a.sort());
});
