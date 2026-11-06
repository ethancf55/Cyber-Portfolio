/* NEXUS VORTEX // SYNTHETIC LOAD FIXTURE
   Deterministic Suricata EVE lines for performance tests. Documentation
   address ranges and reserved names only. Shared by the page and Node. */
const NVSynthetic = (() => {
  'use strict';
  function rng(seed) { let a = seed >>> 0; return () => { a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
  const iso = ms => new Date(ms).toISOString().replace('Z', '+0000');
  function large(count = 50000, seed = 99) {
    const r = rng(seed);
    const T0 = Date.UTC(2026, 9, 23, 18, 0, 0);
    const internal = Array.from({ length: 200 }, (_, i) => '10.30.' + Math.floor(i / 250) + '.' + (i % 250 + 1));
    const external = Array.from({ length: 2000 }, (_, i) => ['192.0.2.', '198.51.100.', '203.0.113.'][i % 3] + (i % 250 + 1));
    const lines = new Array(count);
    const span = 6 * 3600000, step = span / count;
    let t = T0, beacon = T0 + 600000;
    for (let i = 0; i < count; i++) {
      t += step * (0.5 + r());
      const src = internal[Math.floor(r() * internal.length)], dst = external[Math.floor(r() * external.length)];
      const kind = r();
      let e;
      if (t >= beacon && beacon < T0 + span) {
        e = { timestamp: iso(beacon + 300), event_type: 'flow', src_ip: '10.30.0.77', src_port: 40000 + (i % 20000), dest_ip: '198.51.100.250', dest_port: 8443, proto: 'TCP', flow: { start: iso(beacon), end: iso(beacon + 300), bytes_toserver: 300, bytes_toclient: 900, state: 'closed' } };
        beacon += 120000 + Math.floor((r() - 0.5) * 2000);
      } else if (kind < 0.55) e = { timestamp: iso(t + 2000), flow_id: i, event_type: 'flow', src_ip: src, src_port: 30000 + (i % 30000), dest_ip: dst, dest_port: [443, 80, 8080, 22][Math.floor(r() * 4)], proto: 'TCP', flow: { start: iso(t), end: iso(t + 2000), bytes_toserver: Math.floor(r() * 9000), bytes_toclient: Math.floor(r() * 90000), state: 'closed' } };
      else if (kind < 0.85) e = { timestamp: iso(t), flow_id: i, event_type: 'dns', src_ip: '10.30.0.2', src_port: 53, dest_ip: src, dest_port: 30000 + (i % 30000), proto: 'UDP', dns: { type: 'answer', rrname: 'host' + (i % 3000) + '.example.com', rrtype: 'A', rcode: r() < 0.03 ? 'NXDOMAIN' : 'NOERROR', answers: [{ rrname: 'host' + (i % 3000) + '.example.com', rrtype: 'A', rdata: dst }] } };
      else if (kind < 0.995) e = { timestamp: iso(t), flow_id: i, event_type: 'http', src_ip: src, src_port: 30000 + (i % 30000), dest_ip: dst, dest_port: 80, proto: 'TCP', http: { hostname: 'site' + (i % 500) + '.example.org', url: '/path/' + (i % 977), http_method: 'GET', status: 200, http_user_agent: 'SyntheticBrowser/1.0' } };
      else e = { timestamp: iso(t), flow_id: i, event_type: 'alert', src_ip: src, src_port: 30000 + (i % 30000), dest_ip: dst, dest_port: 443, proto: 'TCP', alert: { signature: 'NV SYNTHETIC policy alert ' + (i % 7), signature_id: 9100000 + (i % 7), severity: 3 } };
      lines[i] = JSON.stringify(e);
    }
    return lines.join('\n') + '\n';
  }
  return { large };
})();
if (typeof module !== 'undefined' && module.exports) module.exports = NVSynthetic;
