const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Core, NOW, ingest, ingestDir, fs, path, FIXTURES } = require('./helpers.js');

test('SHA-256 agrees with Node crypto across block boundaries and Unicode', () => {
  const inputs = ['', 'abc'];
  for (const n of [55, 56, 63, 64, 65, 119, 120, 1000, 70000]) inputs.push('a'.repeat(n));
  inputs.push('héllo ✓ 𝄞 日本', '\u0000\u00ff');
  const rnd = crypto.randomBytes(5000);
  assert.equal(Core.sha256Bytes(new Uint8Array(rnd)), crypto.createHash('sha256').update(rnd).digest('hex'));
  for (const s of inputs) assert.equal(Core.sha256Text(s), crypto.createHash('sha256').update(s, 'utf8').digest('hex'), 'length ' + s.length);
});

test('canonical JSON is independent of key order and rejects non-finite numbers', () => {
  assert.equal(Core.canonicalJSON({ b: 1, a: { d: [1, { z: 1, y: 2 }], c: null } }), Core.canonicalJSON({ a: { c: null, d: [1, { y: 2, z: 1 }] }, b: 1 }));
  assert.equal(Core.canonicalJSON({ a: undefined, b: 2 }), '{"b":2}');
  assert.throws(() => Core.canonicalJSON({ a: NaN }));
});

test('timestamps: explicit zones, epochs and assumptions are distinguished', () => {
  const o = { now: NOW };
  const t = v => Core.parseTimestamp(v, o);
  assert.deepEqual([t('2026-10-23T19:00:00Z').ms, t('2026-10-23T19:00:00Z').quality], [Date.UTC(2026, 9, 23, 19), 'explicit-zone']);
  assert.equal(t('2026-10-23T19:00:00.5+0000').ms, Date.UTC(2026, 9, 23, 19, 0, 0, 500));
  assert.equal(t('2026-10-23T19:00:00+05:30').ms, Date.UTC(2026, 9, 23, 13, 30));
  assert.equal(t('2026-10-23 19:00:00').quality, 'assumed-zone');
  assert.equal(Core.parseTimestamp('2026-10-23 19:00:00', { now: NOW, zoneOffsetMinutes: 60 }).ms, Date.UTC(2026, 9, 23, 18));
  const sys = Core.parseTimestamp('Oct  3 04:05:06', { now: NOW, syslogYear: 2025 });
  assert.equal(sys.quality, 'assumed-year');
  assert.equal(sys.ms, Date.UTC(2025, 9, 3, 4, 5, 6));
  assert.equal(t('1792782000.25').ms, 1792782000250);
  assert.equal(t(1792782000250).quality, 'epoch');
  assert.equal(t('05/06/2026 10:00').quality, 'ambiguous');
  assert.equal(Core.parseTimestamp('05/06/2026 10:00', { now: NOW, slashOrder: 'dmy' }).ms, Date.UTC(2026, 5, 5, 10));
  assert.equal(Core.parseTimestamp('05/06/2026 10:00', { now: NOW, slashOrder: 'mdy' }).ms, Date.UTC(2026, 4, 6, 10));
  assert.equal(t('13/06/2026 10:00').ms, Date.UTC(2026, 5, 13, 10), 'unambiguous day-first');
  assert.equal(t('10/23/2026 7:00 PM').ms, Date.UTC(2026, 9, 23, 19));
  assert.equal(t('2026-02-30T00:00:00Z').quality, 'unparseable');
  assert.equal(t('1970-01-01T00:00:00Z').quality, 'implausible');
  assert.equal(t(new Date(NOW + 10 * 86400000).toISOString()).quality, 'implausible');
  assert.equal(t('-').quality, 'missing');
  assert.equal(t('yesterday').quality, 'unparseable');
  assert.equal(t('2026-06-30T23:59:60Z').ms, Date.UTC(2026, 5, 30, 23, 59, 59));
});

test('addresses: validation and scope', () => {
  assert.equal(Core.normalizeIP('010.001.002.003'), '10.1.2.3');
  for (const bad of ['999.1.1.1', '1.2.3', '::1::2', '<img src=x>', 'example.com', '']) assert.equal(Core.normalizeIP(bad), null, bad);
  assert.equal(Core.normalizeIP('[FE80::1]'), 'fe80::1');
  assert.equal(Core.ipScope('10.2.3.4'), 'internal');
  assert.equal(Core.ipScope('172.31.0.1'), 'internal');
  assert.equal(Core.ipScope('172.32.0.1'), 'external');
  assert.equal(Core.ipScope('198.51.100.7'), 'documentation');
  assert.equal(Core.ipScope('fd00::1'), 'internal');
  assert.ok(Core.isExternal('203.0.113.9') && !Core.isInternal('203.0.113.9'));
});

test('format detection recognises each supported fixture and refuses unknown text', () => {
  const read = p => fs.readFileSync(path.join(FIXTURES, p), 'utf8');
  assert.equal(Core.detectFormat(read('suspicious/eve.json')).format, 'suricata-eve');
  assert.equal(Core.detectFormat(read('suspicious/conn.log')).format, 'zeek-tsv');
  assert.equal(Core.detectFormat(read('suspicious/auth.log')).format, 'syslog-auth');
  assert.equal(Core.detectFormat(read('timestamps/idp-signins.csv'), 'idp-signins.csv').format, 'auth-csv');
  assert.equal(Core.detectFormat(read('malformed/unknown.txt')).format, null);
  assert.equal(Core.detectFormat(read('malformed/auth-missing-columns.csv'), 'x.csv').format, null);
  assert.equal(Core.detectFormat('[{"EventID":4625,"TargetUserName":"a"}]').format, 'windows-auth-json');
});

test('every input line is accounted for in the receipt', () => {
  for (const dir of ['benign', 'suspicious', 'malformed', 'timestamps', 'hostile']) {
    const { receipts } = ingestDir(dir);
    for (const r of receipts) {
      if (r.status === 'unrecognized' || r.status === 'failed') { assert.ok(r.error, r.fileName + ' explains its failure'); continue; }
      const accounted = r.accepted + r.rejected + r.duplicates.withinFile + r.duplicates.acrossImports + r.metadataLines + r.blankLines;
      assert.equal(accounted, r.linesRead, dir + '/' + r.fileName);
      assert.equal(r.rejectedLines.reduce((n, [a, b]) => n + b - a + 1, 0), r.rejected, 'rejected line ranges cover every rejection');
    }
  }
});

test('Suricata EVE: direction normalisation, flow start, conflicts and per-field validation', () => {
  const lines = [
    { timestamp: '2026-10-23T18:00:00.000000+0000', event_type: 'dns', src_ip: '10.0.0.2', src_port: 53, dest_ip: '10.0.0.9', dest_port: 5000, dns: { type: 'answer', rrname: 'A.Example.', rcode: 'NOERROR', answers: [{ rrtype: 'A', rdata: '192.0.2.1' }, { rrtype: 'CNAME', rdata: 'b.example' }] } },
    { timestamp: '2026-10-23T18:10:00+0000', event_type: 'flow', src_ip: '10.0.0.9', dest_ip: '192.0.2.1', dest_port: 443, flow: { start: '2026-10-23T18:01:00+0000' } },
    { timestamp: '2026-10-23T18:00:00Z', '@timestamp': '2026-10-23T20:00:00Z', event_type: 'alert', src_ip: 'nonsense', dest_port: 99999, alert: { signature: 'x', severity: 1 } },
    { timestamp: '2026-10-23T18:00:00Z', event_type: 'dns', dns: { version: 3, type: 'response', queries: [{ rrname: 'v3.example', rrtype: 'AAAA' }], answers: [{ rrtype: 'AAAA', rdata: '2001:db8::1' }], rcode: 'NOERROR' } }
  ].map(o => JSON.stringify(o)).join('\n');
  const { records, receipt } = ingest(lines, { fileName: 'eve.json' });
  assert.equal(receipt.format, 'suricata-eve');
  const [dns, flow, alert, v3] = records;
  assert.deepEqual([dns.src, dns.dst, dns.query, dns.answers], ['10.0.0.9', '10.0.0.2', 'a.example', ['192.0.2.1']]);
  assert.equal(flow.time, Date.UTC(2026, 9, 23, 18, 1));
  assert.equal(alert.conflicts[0].type, 'timestamp');
  assert.equal(alert.src, null);
  assert.equal(alert.port, null);
  assert.equal(alert.notes.length, 2);
  assert.equal(alert.severity, 'high');
  assert.deepEqual(v3.answers, ['2001:db8::1']);
  assert.equal(receipt.conflicts.timestamp, 1);
});

test('duplicates are counted with their first-seen location, within and across imports', () => {
  const line = JSON.stringify({ timestamp: '2026-10-23T18:00:00Z', event_type: 'flow', src_ip: '10.0.0.1', dest_ip: '192.0.2.1', flow: { start: '2026-10-23T18:00:00Z' } });
  const session = Core.createSession();
  const a = ingest(line + '\n' + line + '\n', { importId: 'A', fileName: 'a.json', session });
  const b = ingest(line + '\n', { importId: 'B', fileName: 'b.json', session });
  assert.equal(a.records.length, 1);
  assert.equal(a.receipt.duplicates.withinFile, 1);
  assert.equal(b.records.length, 0);
  assert.equal(b.receipt.duplicates.acrossImports, 1);
  assert.deepEqual(b.duplicates[0], { id: 'A:1', location: { importId: 'B', source: 'b.json', line: 1 } });
  Core.removeImportFromSession(session, 'A');
  assert.equal(ingest(line, { importId: 'C', fileName: 'c.json', session }).records.length, 1, 'removing an import forgets its fingerprints');
});

test('Zeek TSV: header handling, unset fields, field-count rejection and uid conflicts', () => {
  const { receipts, records, annotations } = ingestDir('malformed');
  const zeek = receipts.find(r => r.fileName === 'conn.log');
  assert.deepEqual(zeek.rejectSamples.map(s => [s.line, s.reason]), [[1, 'Zeek data line before a #fields header'], [11, 'Expected 12 tab-separated fields, found 3']]);
  const bad = records.find(r => r.source === 'conn.log' && r.uid === 'zeek:Cm2');
  assert.equal(bad.src, null);
  assert.ok(bad.notes.some(n => /not a valid IP/.test(n)) && bad.notes.some(n => /not a valid port/.test(n)));
  const sus = ingestDir('suspicious');
  const conflicted = sus.records.filter(r => r.uid === 'zeek:CBconflict');
  assert.equal(conflicted.length, 2);
  assert.equal(conflicted[1].conflicts[0].otherId, conflicted[0].id);
  assert.ok(sus.annotations.some(a => a.id === conflicted[0].id && a.conflict.otherId === conflicted[1].id), 'earlier record is annotated too');
  const untimed = sus.records.find(r => r.uid === 'zeek:CBnots');
  assert.equal(untimed.time, null);
  assert.equal(untimed.timeQuality, 'missing');
  void annotations;
});

test('syslog authentication parsing keeps hostile text verbatim and does not double count notices', () => {
  const { records } = ingestDir('suspicious');
  const auth = records.filter(r => r.source === 'auth.log');
  const hostile = auth.find(r => r.user && r.user.includes('<img'));
  assert.equal(hostile.user, "<img src=x onerror=alert('nv-auth')>");
  assert.equal(hostile.outcome, 'failure');
  assert.ok(auth.filter(r => r.outcome === 'notice').every(r => /^sshd: Invalid user/.test(r.message)));
  const repeated = auth.find(r => r.repeat === 2);
  assert.equal(repeated.user, 'root');
  const iso = ingest('2026-10-23T18:02:00.123456+00:00 vpn-01 sshd[11]: Accepted publickey for ops from 10.20.0.60 port 50001 ssh2\n<38>1 2026-10-23T18:03:00Z vpn-01 sshd 12 - - Failed password for ops from 10.20.0.61 port 50002 ssh2', { fileName: 'x.log' }).records;
  assert.deepEqual(iso.map(r => [r.outcome, r.user, r.src, r.timeQuality]), [['success', 'ops', '10.20.0.60', 'explicit-zone'], ['failure', 'ops', '10.20.0.61', 'explicit-zone']]);
});

test('authentication CSV: column mapping, recovery from bad quotes, conflicts and unknown outcomes', () => {
  const { receipts, records } = ingestDir('timestamps');
  const csv = receipts.find(r => r.format === 'auth-csv');
  assert.deepEqual(csv.columnMapping, { time: 'timestamp', user: 'user', src: 'src_ip', outcome: 'result', host: 'app', id: 'event_id' });
  assert.deepEqual(csv.timeQuality, { 'explicit-zone': 5, 'assumed-zone': 2, epoch: 1, ambiguous: 1, missing: 1, unparseable: 1, implausible: 1 });
  assert.equal(csv.duplicates.withinFile, 1);
  assert.equal(csv.conflicts.identity, 1);
  assert.equal(csv.conflicts.timestamp, 1);
  assert.equal(records.find(r => r.user === 'mallory@corp.example').outcome, 'unknown');
  const forced = ingest('when,who\n2026-10-23T18:00:00Z,alice\n', { format: 'auth-csv' }).receipt;
  assert.equal(forced.status, 'failed');
  assert.match(forced.error, /missing required column\(s\): time, outcome, user or source IP/);
  const quotes = ingestDir('malformed').receipts.find(r => r.fileName === 'auth-quotes.csv');
  assert.equal(quotes.accepted, 1);
  assert.deepEqual(quotes.rejectSamples.map(s => s.line), [2, 4]);
});

test('limits: retention stop, raw truncation and oversized lines are reported, not hidden', () => {
  const line = i => JSON.stringify({ timestamp: '2026-10-23T18:00:00Z', event_type: 'flow', src_ip: '10.0.0.1', dest_ip: '192.0.2.1', src_port: i, flow: { start: '2026-10-23T18:00:00Z' } });
  const text = Array.from({ length: 50 }, (_, i) => line(i)).join('\n');
  const limited = ingest(text, { maxRecords: 20 });
  assert.equal(limited.records.length, 20);
  assert.equal(limited.receipt.status, 'limit');
  assert.equal(limited.receipt.limit.atLine, 21);
  const big = JSON.stringify({ timestamp: '2026-10-23T18:00:00Z', event_type: 'http', src_ip: '10.0.0.1', http: { url: 'x'.repeat(30000) } });
  const t = ingest(big);
  assert.equal(t.records[0].rawTruncated, true);
  assert.equal(t.records[0].raw.length, Core.RAW_LIMIT);
  assert.equal(t.records[0].rawSha256, crypto.createHash('sha256').update(big).digest('hex'), 'digest covers the full original line');
  assert.equal(t.receipt.rawTruncated, 1);
  const huge = ingest('{"event_type":"x","pad":"' + 'y'.repeat(Core.LINE_LIMIT + 10) + '"}\n' + line(1));
  assert.equal(huge.receipt.rejected, 1);
  assert.match(huge.receipt.rejectSamples[0].reason, /1 MiB/);
  assert.equal(huge.records.length, 1, 'the following line still imports');
});

test('streaming chunks split mid-line and CRLF produce the same records as a single push', () => {
  const text = fs.readFileSync(path.join(FIXTURES, 'suspicious/conn.log'), 'utf8').replace(/\n/g, '\r\n');
  const whole = ingest(text, { fileName: 'conn.log' });
  const ing = Core.createIngestor({ importId: 'T', fileName: 'conn.log', options: { now: NOW } });
  for (let i = 0; i < text.length; i += 97) ing.push(text.slice(i, i + 97));
  ing.finish();
  const chunked = ing.drain().records;
  assert.deepEqual(chunked.map(r => [r.id, r.rawSha256]), whole.records.map(r => [r.id, r.rawSha256]));
});

test('cancellation seals the receipt with the stopping point', () => {
  const ing = Core.createIngestor({ importId: 'T', fileName: 'x', options: { now: NOW } });
  ing.push(fs.readFileSync(path.join(FIXTURES, 'suspicious/eve.json'), 'utf8'));
  const r = ing.cancel();
  assert.equal(r.status, 'cancelled');
  assert.ok(r.cancelled.bytesRead > 0);
});
