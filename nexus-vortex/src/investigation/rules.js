/* NEXUS VORTEX // DETERMINISTIC CORRELATION RULES
   Input: normalized evidence records (see core.js). Output: findings that cite
   the exact supporting record IDs, thresholds, windows, assets and limits. */
const NVRules = (() => {
  'use strict';
  const Core = typeof NVCore !== 'undefined' ? NVCore : require('./core.js');
  const RULESET = 'NV-RULESET 2026.11-1';
  const MIN = 60000;

  const RULES = {
    'NV-AUTH-002': { version: '1.0.0', title: 'Authentication failures followed by a success', requires: 'Authentication records with outcome, timestamps, and a source address or host/account.',
      params: { lookbackMs: 10 * MIN, minFailures: 5 } },
    'NV-AUTH-001': { version: '2.0.0', title: 'Repeated authentication failures', requires: 'Authentication failure records with timestamps.',
      params: { windowMs: 5 * MIN, minFailures: 5 }, supersedes: 'AUTH-BURST-5 (v1, Security Fabric)' },
    'NV-NET-001': { version: '1.0.0', title: 'Unusually regular outbound connections', requires: 'Connection records (Zeek conn, Suricata flow) with timestamps, internal source and external destination.',
      params: { minConnections: 8, minMedianMs: 10000, maxMedianMs: 6 * 3600000, tolerance: 0.15, minToleranceMs: 2000, minRegularFraction: 0.8, excludedPorts: [53, 123, 5353] } },
    'NV-DNS-001': { version: '1.0.0', title: 'NXDOMAIN burst, then a resolution and a connection to the resolved address', requires: 'DNS responses with response codes and A/AAAA answers, plus connection records from the same client.',
      params: { burstWindowMs: 5 * MIN, minDistinctNx: 10, resolveWithinMs: 5 * MIN, connectWithinMs: 120000 } },
    'NV-SRC-001': { version: '1.0.0', title: 'Source-reported alert', requires: 'Alert records from a sensor (Suricata EVE alert) or source-assigned high severity from adapters.', params: {} },
    'NV-EXEC-001': { version: '1.1.0', title: 'Encoded PowerShell command line', requires: 'Text containing command lines.', params: {}, supersedes: 'EXEC-ENCODED (v1, Security Fabric)' },
    'NV-SVC-001': { version: '1.1.0', title: 'Reachable service to review', requires: 'Scan results with open-port state.', params: { ports: [23, 445, 3389, 5900, 6379, 9200, 27017] }, supersedes: 'SERVICE-REVIEW (v1, Security Fabric)' }
  };
  const LEVELS = ['low', 'moderate', 'high'];
  const raise = level => LEVELS[Math.min(LEVELS.length - 1, LEVELS.indexOf(level) + 1)] || level;
  const EXACT = new Set(['explicit-zone', 'epoch']);

  const accountKey = r => 'user:' + r.user + '@' + (r.host || 'unknown');
  const domainKey = d => 'dns:' + d;
  function median(values) { const s = values.slice().sort((a, b) => a - b), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; }
  function makeId(ruleId, key, firstId) { return 'F-' + Core.sha256Text(ruleId + '|' + key + '|' + firstId).slice(0, 12); }
  function timeCompleteness(records, notes) {
    const assumed = records.filter(r => !EXACT.has(r.timeQuality)).length;
    if (assumed) notes.push(assumed + ' of ' + records.length + ' supporting timestamps rely on an import assumption (zone or year).');
    return assumed === 0;
  }
  function finding(ruleId, key, base) {
    const rule = RULES[ruleId];
    const ids = base.evidenceIds;
    return {
      id: makeId(ruleId, key, ids[0]), ruleId, ruleVersion: rule.version, ruleset: RULESET, ruleTitle: rule.title, key,
      related: [], corroboration: [], ...base, evidenceTotal: ids.length
    };
  }
  /* Densest window of width `width` over sorted items with weights. */
  function densest(items, width, weight = () => 1) {
    let best = { lo: 0, hi: -1, total: 0 }, total = 0, lo = 0;
    for (let hi = 0; hi < items.length; hi++) {
      total += weight(items[hi]);
      while (items[hi].time - items[lo].time > width) { total -= weight(items[lo]); lo++; }
      if (total > best.total) best = { lo, hi, total };
    }
    return best;
  }
  function clusters(items, gap) {
    const out = []; let cur = [];
    for (const r of items) { if (cur.length && r.time - cur[cur.length - 1].time > gap) { out.push(cur); cur = []; } cur.push(r); }
    if (cur.length) out.push(cur);
    return out;
  }

  function evaluate(records, options = {}) {
    const started = Date.now();
    const findings = [], coverage = [];
    const auth = [], conns = [], dns = [], alerts = [], textual = [], scans = [];
    let untimedAuth = 0, untimedConn = 0, untimedDns = 0;
    for (const r of records) {
      if (r.kind === 'auth' || (r.kind === 'ssh' && r.outcome)) { if (r.time == null) untimedAuth++; else auth.push(r); }
      else if (r.kind === 'conn') { if (r.time == null) untimedConn++; else conns.push(r); }
      else if (r.kind === 'dns') { if (r.time == null) untimedDns++; else dns.push(r); }
      if (r.kind === 'alert' || (r.severity === 'high' && (r.format === 'legacy-adapter' || r.format === 'live'))) alerts.push(r);
      if (r.kind === 'text' || r.kind === 'syslog' || r.format === 'legacy-adapter' || r.format === 'live') textual.push(r);
      if (r.kind === 'scan') scans.push(r);
    }
    const byTime = (a, b) => a.time - b.time;
    auth.sort(byTime); conns.sort(byTime); dns.sort(byTime);

    /* ------------------------------------------------ NV-AUTH-002 / NV-AUTH-001 */
    {
      const p2 = RULES['NV-AUTH-002'].params, p1 = RULES['NV-AUTH-001'].params;
      const groups = new Map();
      for (const r of auth) {
        if (r.outcome !== 'failure' && r.outcome !== 'success') continue;
        const key = r.src ? 'src:' + r.src : 'acct:' + (r.host || 'unknown') + '/' + (r.user || 'unknown');
        let g = groups.get(key); if (!g) groups.set(key, g = { failures: [], successes: [] });
        (r.outcome === 'failure' ? g.failures : g.successes).push(r);
      }
      let covered = new Set(), found2 = 0, found1 = 0, pamOnlyKeys = 0;
      for (const [key, g] of groups) {
        const service = g.failures.filter(r => r.authLayer !== 'pam');
        const failures = service.length ? service : g.failures;
        if (!service.length && g.failures.length) pamOnlyKeys++;
        const weight = r => r.repeat || 1;
        /* AUTH-002: for each success, count failures in the preceding lookback. */
        let open = null;
        const flush = () => {
          if (!open) return;
          const fails = open.failures, succ = open.successes, first = succ[0];
          const failedAccounts = [...new Set(fails.map(r => r.user).filter(Boolean))];
          const weighted = fails.reduce((n, r) => n + weight(r), 0);
          const targeted = failedAccounts.includes(first.user);
          const lastFail = fails[fails.length - 1];
          const gap = (first.time - lastFail.time) / 1000;
          const support = [...fails, ...succ];
          const notes = [];
          const exact = timeCompleteness(support, notes);
          if (!first.src) notes.push('No source address in these records; failures were grouped by host and account instead.');
          if (fails.some(r => !r.user)) notes.push('Some failures lack an account name.');
          if (!service.length) notes.push('Only PAM-layer failure lines were available; PAM and service lines can describe the same attempt.');
          let confidence = 'moderate';
          const basis = [];
          if (weighted >= 10 && failedAccounts.length >= 3 && exact) { confidence = 'high'; basis.push('≥10 failures across ≥3 accounts with exact timestamps.'); }
          else if (failedAccounts.length <= 1 && weighted < 10) { confidence = 'low'; basis.push('Failures target a single account; a user mistyping a password produces the same sequence.'); }
          else basis.push(weighted + ' failures across ' + failedAccounts.length + ' account(s) preceded the success.');
          if (gap > 300) { confidence = confidence === 'high' ? 'moderate' : 'low'; basis.push('The success came ' + Math.round(gap) + ' s after the last failure, weakening the link.'); }
          const assets = [];
          if (first.src) assets.push({ key: first.src, kind: 'ip', role: 'source of attempts' });
          for (const u of new Set(support.filter(r => r.user).map(accountKey))) assets.push({ key: u, kind: 'account', role: u === accountKey(first) ? 'account that logged on' : 'account targeted' });
          for (const h of new Set(support.map(r => r.host).filter(Boolean))) assets.push({ key: 'host:' + h, kind: 'host', role: 'system that logged the events' });
          const f = finding('NV-AUTH-002', key, {
            title: 'Successful logon for ' + (first.user || 'unknown account') + ' after ' + weighted + ' failures from ' + (first.src || 'the same host/account'),
            summary: weighted + ' authentication failures' + (failedAccounts.length > 1 ? ' across ' + failedAccounts.length + ' accounts' : '') + ' within ' + Math.round(p2.lookbackMs / MIN) + ' minutes were followed by a successful logon for ' + (first.user || 'an unknown account') + (targeted ? ' (an account that had failed)' : '') + ', ' + Math.round(gap) + ' s after the last failure.',
            interpretation: 'The success may have resulted from password guessing rather than a legitimate user.',
            severity: 'high', severityBasis: 'An account session was established after repeated failures; if unauthorised, the account is compromised.',
            confidence, confidenceBasis: basis,
            completeness: exact && first.src && !fails.some(r => !r.user) ? 'complete' : 'partial', completenessNotes: notes,
            window: { start: fails[0].time, end: succ[succ.length - 1].time },
            thresholds: [
              { name: 'Failures in lookback before success', threshold: '≥ ' + p2.minFailures, observed: weighted, met: true },
              { name: 'Lookback window', threshold: Math.round(p2.lookbackMs / MIN) + ' min', observed: Math.round((first.time - fails[0].time) / 1000) + ' s span', met: true },
              { name: 'Distinct accounts failed', threshold: 'reported', observed: failedAccounts.length, met: null },
              { name: 'Success account previously failed', threshold: 'reported', observed: targeted ? 'yes' : 'no', met: null }
            ],
            evidenceIds: support.map(r => r.id),
            assets,
            edges: first.src ? [...new Set(support.filter(r => r.user).map(accountKey))].map(u => ({ a: first.src, b: u, kind: 'auth', basis: 'Authentication records name this source and account.' })) : [],
            alternatives: [
              targeted && failedAccounts.length <= 1 ? 'The account owner mistyped the password several times, then succeeded.' : 'A user mistyped a password repeatedly before succeeding.',
              'A script or service retried stale credentials until they were updated.',
              'The source address is a shared NAT, VPN or proxy egress used by several people.',
              'Authorised security testing.'
            ],
            missingContext: [
              'Multi-factor or second-factor logs for this logon.',
              'What the session did after logon (commands, processes, file access).',
              'Whether the source address belongs to a known VPN, NAT or bastion.',
              'Authentication logs from other systems that this source may also have tried.'
            ],
            nextSteps: [
              'Review activity for ' + (first.user || 'the account') + ' on ' + (first.host || 'the logging host') + ' after ' + new Date(first.time).toISOString() + '.',
              'Search for other activity from ' + (first.src || 'this source') + ' across all imported evidence.',
              'Confirm with the account owner whether the logon was theirs.'
            ]
          });
          findings.push(f); found2++;
          for (const r of fails) covered.add(r.id);
          open = null;
        };
        let fi = 0;
        const window = [];
        for (const s of g.successes) {
          while (fi < failures.length && failures[fi].time < s.time) window.push(failures[fi++]);
          while (window.length && s.time - window[0].time > p2.lookbackMs) window.shift();
          const weighted = window.reduce((n, r) => n + weight(r), 0);
          if (weighted >= p2.minFailures) {
            if (open && window[0].time <= open.failures[open.failures.length - 1].time) {
              for (const r of window) if (!open.failures.includes(r)) open.failures.push(r);
              open.successes.push(s);
            } else { flush(); open = { failures: window.slice(), successes: [s] }; }
          }
        }
        flush();
        /* AUTH-001: bursts not already explained by an AUTH-002 finding. */
        for (const cluster of clusters(failures, p1.windowMs)) {
          const best = densest(cluster, p1.windowMs, weight);
          if (best.total < p1.minFailures) continue;
          if (cluster.every(r => covered.has(r.id))) continue;
          const accounts = [...new Set(cluster.map(r => r.user).filter(Boolean))];
          const notes = [];
          const exact = timeCompleteness(cluster, notes);
          const assets = [];
          if (cluster[0].src) assets.push({ key: cluster[0].src, kind: 'ip', role: 'source of attempts' });
          for (const u of new Set(cluster.filter(r => r.user).map(accountKey))) assets.push({ key: u, kind: 'account', role: 'account targeted' });
          for (const h of new Set(cluster.map(r => r.host).filter(Boolean))) assets.push({ key: 'host:' + h, kind: 'host', role: 'system that logged the events' });
          const total = cluster.reduce((n, r) => n + weight(r), 0);
          findings.push(finding('NV-AUTH-001', key, {
            title: total + ' authentication failures from ' + (cluster[0].src || 'one host/account') + (accounts.length > 1 ? ' across ' + accounts.length + ' accounts' : ''),
            summary: best.total + ' failures fell within ' + Math.round(p1.windowMs / MIN) + ' minutes (' + total + ' in the whole burst). No success from this source followed within ' + Math.round(p2.lookbackMs / MIN) + ' minutes.',
            interpretation: 'Password guessing or spraying against these accounts.',
            severity: accounts.length >= 3 || total >= 20 ? 'medium' : 'low', severityBasis: 'No successful logon followed in the evidence; impact depends on whether attempts continue elsewhere.',
            confidence: accounts.length >= 3 ? 'moderate' : 'low', confidenceBasis: [accounts.length >= 3 ? 'Several distinct accounts were tried.' : 'A single account was tried; misconfigured clients produce the same pattern.'],
            completeness: exact && cluster[0].src ? 'complete' : 'partial', completenessNotes: notes,
            window: { start: cluster[0].time, end: cluster[cluster.length - 1].time },
            thresholds: [
              { name: 'Failures in densest window', threshold: '≥ ' + p1.minFailures, observed: best.total, met: true },
              { name: 'Window', threshold: Math.round(p1.windowMs / MIN) + ' min', observed: Math.round((cluster[best.hi].time - cluster[best.lo].time) / 1000) + ' s', met: true },
              { name: 'Distinct accounts', threshold: 'reported', observed: accounts.length, met: null }
            ],
            evidenceIds: cluster.map(r => r.id), assets,
            edges: cluster[0].src ? [...new Set(cluster.filter(r => r.user).map(accountKey))].map(u => ({ a: cluster[0].src, b: u, kind: 'auth', basis: 'Authentication failure records name this source and account.' })) : [],
            alternatives: ['A misconfigured client or service retrying an old password.', 'A user locked out and retrying.', 'Authorised testing or vulnerability scanning.'],
            missingContext: ['Logs from other authentication sources this address may have tried.', 'Account lockout or rate-limit events.', 'Firewall/VPN records for the source.'],
            nextSteps: ['Check whether ' + (cluster[0].src || 'this source') + ' appears in other evidence.', 'Check lockout policy and whether any of these accounts later logged on from elsewhere.']
          }));
          found1++;
        }
      }
      const hasAuth = auth.length + untimedAuth > 0;
      coverage.push({ ruleId: 'NV-AUTH-002', version: RULES['NV-AUTH-002'].version, title: RULES['NV-AUTH-002'].title, status: hasAuth ? 'evaluated' : 'not-applicable', evaluated: auth.length, excluded: untimedAuth ? { 'no usable timestamp': untimedAuth } : {}, findings: found2,
        detail: hasAuth ? groups.size + ' source/account groups evaluated.' + (pamOnlyKeys ? ' ' + pamOnlyKeys + ' group(s) had only PAM-layer failures.' : '') : 'No authentication records were imported; this rule cannot run.' });
      coverage.push({ ruleId: 'NV-AUTH-001', version: RULES['NV-AUTH-001'].version, title: RULES['NV-AUTH-001'].title, status: hasAuth ? 'evaluated' : 'not-applicable', evaluated: auth.length, excluded: untimedAuth ? { 'no usable timestamp': untimedAuth } : {}, findings: found1,
        detail: hasAuth ? 'Bursts already explained by NV-AUTH-002 are not repeated here.' : 'No authentication records were imported; this rule cannot run.' });
    }

    /* ------------------------------------------------ NV-NET-001 */
    {
      const p = RULES['NV-NET-001'].params;
      const series = new Map();
      let internalOnly = 0, excludedPort = 0, missingAddr = 0, eligible = 0, irregular = 0, found = 0;
      for (const r of conns) {
        if (!r.src || !r.dst) { missingAddr++; continue; }
        if (!Core.isInternal(r.src) || !Core.isExternal(r.dst)) { internalOnly++; continue; }
        if (p.excludedPorts.includes(r.port)) { excludedPort++; continue; }
        const key = [r.src, r.dst, r.port ?? '?', r.proto || '?'].join('|');
        let list = series.get(key); if (!list) series.set(key, list = []);
        list.push(r);
      }
      for (const [key, list] of series) {
        if (list.length < p.minConnections) continue;
        eligible++;
        const intervals = [];
        for (let i = 1; i < list.length; i++) intervals.push(list[i].time - list[i - 1].time);
        const m = median(intervals);
        const tol = Math.max(p.minToleranceMs, p.tolerance * m);
        const regular = intervals.filter(v => Math.abs(v - m) <= tol).length;
        const fraction = regular / intervals.length;
        const mad = median(intervals.map(v => Math.abs(v - m)));
        if (m < p.minMedianMs || m > p.maxMedianMs || fraction < p.minRegularFraction) { irregular++; continue; }
        const [src, dst, port, proto] = key.split('|');
        const notes = [];
        const exact = timeCompleteness(list, notes);
        if (list.some(r => r.format === 'suricata-eve')) notes.push('Suricata flow records use flow.start; flows still open when logging stopped are absent.');
        notes.push('Process attribution is not available in network logs.');
        const confidence = list.length >= 20 && fraction >= 0.9 && mad / m <= 0.05 ? 'moderate' : 'low';
        findings.push(finding('NV-NET-001', key, {
          title: 'Regular ' + Math.round(m / 1000) + ' s connections ' + src + ' → ' + dst + ':' + port,
          summary: list.length + ' connections from ' + src + ' to ' + dst + ':' + port + '/' + proto + ' over ' + Math.round((list[list.length - 1].time - list[0].time) / MIN) + ' minutes. ' + regular + ' of ' + intervals.length + ' intervals fall within ±' + (tol / 1000).toFixed(1) + ' s of the ' + (m / 1000).toFixed(1) + ' s median.',
          interpretation: 'Machine-timed communication, which may be command-and-control beaconing or legitimate software (updates, telemetry, monitoring).',
          severity: 'medium', severityBasis: 'Periodicity alone does not establish malicious activity; severity is raised only through corroboration.',
          confidence, confidenceBasis: [confidence === 'moderate' ? '≥20 connections, ≥90% regular intervals and jitter ≤5% of the median.' : 'Regularity met the threshold but with fewer connections or more jitter.', 'Confidence refers to the suspicious interpretation, not to the timing, which is computed exactly.'],
          completeness: exact ? 'complete' : 'partial', completenessNotes: notes,
          window: { start: list[0].time, end: list[list.length - 1].time },
          thresholds: [
            { name: 'Connections in series', threshold: '≥ ' + p.minConnections, observed: list.length, met: true },
            { name: 'Median interval', threshold: (p.minMedianMs / 1000) + ' s – ' + (p.maxMedianMs / 3600000) + ' h', observed: (m / 1000).toFixed(2) + ' s', met: true },
            { name: 'Intervals within tolerance', threshold: '≥ ' + Math.round(p.minRegularFraction * 100) + '% within ±max(' + p.minToleranceMs / 1000 + ' s, ' + Math.round(p.tolerance * 100) + '%)', observed: Math.round(fraction * 1000) / 10 + '%', met: true },
            { name: 'Median absolute deviation', threshold: 'reported', observed: (mad / 1000).toFixed(2) + ' s', met: null },
            { name: 'Excluded destination ports', threshold: p.excludedPorts.join(', '), observed: port, met: null }
          ],
          evidenceIds: list.map(r => r.id),
          assets: [{ key: src, kind: 'ip', role: 'internal source' }, { key: dst, kind: 'ip', role: 'external destination' }],
          edges: [{ a: src, b: dst, kind: 'comm', basis: list.length + ' connection records from ' + src + ' to ' + dst + ':' + port + '.' }],
          alternatives: ['Software update or licence checks.', 'Endpoint, backup or monitoring agents reporting on a schedule.', 'Keep-alive traffic of a long-lived application.', 'Browser or application telemetry.'],
          missingContext: ['Which process on ' + src + ' opened the connections.', 'DNS names that resolved to ' + dst + ' (if DNS logs are absent).', 'Payload sizes and TLS details for these sessions.', 'Destination ownership and reputation (no external lookup is performed).'],
          nextSteps: ['Identify the process on ' + src + ' responsible for the connections.', 'Check whether other internal hosts contact ' + dst + '.', 'Compare with the software inventory for scheduled agents.']
        }));
        found++;
      }
      const has = conns.length + untimedConn > 0;
      const internalSeen = conns.some(r => r.src && Core.isInternal(r.src));
      coverage.push({ ruleId: 'NV-NET-001', version: RULES['NV-NET-001'].version, title: RULES['NV-NET-001'].title,
        status: !has ? 'not-applicable' : internalSeen ? 'evaluated' : 'insufficient', evaluated: conns.length,
        excluded: Object.fromEntries(Object.entries({ 'no usable timestamp': untimedConn, 'not internal → external': internalOnly, 'excluded port (DNS/NTP/mDNS)': excludedPort, 'missing address': missingAddr }).filter(([, v]) => v)),
        findings: found,
        detail: !has ? 'No connection records were imported; this rule cannot run.' : !internalSeen ? 'No internal (RFC 1918/ULA) source addresses were seen, so outbound direction cannot be established.' : eligible + ' series had ≥' + p.minConnections + ' connections; ' + irregular + ' were not regular enough to report.' });
    }

    /* ------------------------------------------------ NV-DNS-001 */
    {
      const p = RULES['NV-DNS-001'].params;
      const withRcode = dns.filter(r => r.rcode);
      const nxByClient = new Map(), okByClient = new Map();
      for (const r of withRcode) {
        if (!r.src || !r.query) continue;
        if (r.rcode === 'NXDOMAIN') { let l = nxByClient.get(r.src); if (!l) nxByClient.set(r.src, l = []); l.push(r); }
        else if (r.answers && r.answers.length) { let l = okByClient.get(r.src); if (!l) okByClient.set(r.src, l = []); l.push(r); }
      }
      const connByClient = new Map();
      for (const r of [...conns, ...records.filter(r => (r.kind === 'http' || r.kind === 'tls' || r.kind === 'alert') && r.time != null)]) {
        if (!r.src || !r.dst) continue;
        let l = connByClient.get(r.src); if (!l) connByClient.set(r.src, l = []); l.push(r);
      }
      for (const l of connByClient.values()) l.sort(byTime);
      let bursts = 0, unlinked = 0, found = 0;
      for (const [client, nx] of nxByClient) {
        for (const cluster of clusters(nx, p.burstWindowMs)) {
          const distinct = new Set(cluster.map(r => r.query));
          if (distinct.size < p.minDistinctNx) continue;
          bursts++;
          const start = cluster[0].time, end = cluster[cluster.length - 1].time;
          const candidates = (okByClient.get(client) || []).filter(r => r.time >= start && r.time <= end + p.resolveWithinMs && !distinct.has(r.query));
          let link = null;
          for (const d of candidates) {
            const c = (connByClient.get(client) || []).find(c => d.answers.includes(c.dst) && c.time >= d.time && c.time - d.time <= p.connectWithinMs);
            if (c) { link = { d, c }; break; }
          }
          if (!link) { unlinked++; continue; }
          const { d, c } = link;
          const later = (connByClient.get(client) || []).filter(x => x.dst === c.dst && x.time >= c.time && x.time - c.time <= 3600000).slice(0, 500);
          const support = [...cluster, d, ...later];
          const notes = [];
          const exact = timeCompleteness(support, notes);
          notes.push('Domain reputation was not looked up; no external service is contacted.');
          const thresholds = [
            { name: 'Distinct NXDOMAIN names in burst', threshold: '≥ ' + p.minDistinctNx + ' within ' + p.burstWindowMs / MIN + ' min', observed: distinct.size, met: true },
            { name: 'Resolution after burst', threshold: '≤ ' + p.resolveWithinMs / MIN + ' min after burst end', observed: Math.round((d.time - end) / 1000) + ' s', met: true },
            { name: 'Connection to resolved address', threshold: '≤ ' + p.connectWithinMs / 1000 + ' s after resolution', observed: ((c.time - d.time) / 1000).toFixed(2) + ' s', met: true }
          ];
          findings.push(finding('NV-DNS-001', client + '|' + d.query, {
            title: client + ': ' + distinct.size + ' NXDOMAIN lookups, then ' + d.query + ' → ' + c.dst,
            summary: client + ' received NXDOMAIN for ' + distinct.size + ' distinct names in ' + Math.round((end - start) / 1000) + ' s, then resolved ' + d.query + ' to ' + d.answers.join(', ') + ' and connected to ' + c.dst + (c.port != null ? ':' + c.port : '') + ' ' + ((c.time - d.time) / 1000).toFixed(1) + ' s later.',
            interpretation: 'Domain-generation-style lookups where one name finally resolved and was contacted. The connection is linked to the name by address and timing, which is an inference.',
            severity: 'medium', severityBasis: 'Contact with a host found after many failed lookups merits review; impact is unknown without endpoint data.',
            confidence: 'moderate', confidenceBasis: ['The three-step sequence matched within the configured windows.', 'The name-to-connection link is inferred from a matching address and timing, not from the connection record itself.'],
            completeness: exact ? 'complete' : 'partial', completenessNotes: notes,
            window: { start, end: later[later.length - 1].time },
            thresholds,
            evidenceIds: support.map(r => r.id),
            assets: [{ key: client, kind: 'ip', role: 'client' }, { key: domainKey(d.query), kind: 'domain', role: 'name that resolved' }, { key: c.dst, kind: 'ip', role: 'resolved address contacted' }],
            edges: [
              { a: client, b: domainKey(d.query), kind: 'dns-query', basis: 'DNS record ' + d.id + ': ' + client + ' looked up ' + d.query + '.' },
              { a: domainKey(d.query), b: c.dst, kind: 'dns-answer', basis: 'DNS record ' + d.id + ' answered ' + d.answers.join(', ') + '.' },
              { a: client, b: c.dst, kind: 'comm', basis: 'Connection record ' + c.id + '.' },
              { a: client, b: domainKey(d.query), kind: 'inferred', basis: 'Inferred: ' + client + ' connected to ' + c.dst + ' ' + ((c.time - d.time) / 1000).toFixed(1) + ' s after ' + d.query + ' resolved to it. Another name could share the address.' }
            ],
            alternatives: ['A misconfigured DNS search suffix producing NXDOMAIN for internal names.', 'Mistyped names or browser speculative lookups.', 'Security or ad-blocking software probing names.', 'A captive portal or split-horizon DNS.'],
            missingContext: ['Which process issued the lookups on ' + client + '.', 'Whether other names share ' + c.dst + ' (CDN or shared hosting).', 'Registration and reputation of ' + d.query + '.', 'Payload of the subsequent connections.'],
            nextSteps: ['List all NXDOMAIN names from ' + client + ' and look for an algorithmic pattern.', 'Identify the process on ' + client + ' that contacted ' + c.dst + '.', 'Check whether ' + c.dst + ' also appears in periodic-connection findings.']
          }));
          found++;
        }
      }
      const status = dns.length + untimedDns === 0 ? 'not-applicable' : !withRcode.length ? 'insufficient' : 'evaluated';
      coverage.push({ ruleId: 'NV-DNS-001', version: RULES['NV-DNS-001'].version, title: RULES['NV-DNS-001'].title, status, evaluated: dns.length,
        excluded: Object.fromEntries(Object.entries({ 'no usable timestamp': untimedDns, 'no response code (query-only record)': dns.length - withRcode.length }).filter(([, v]) => v)),
        findings: found,
        detail: status === 'not-applicable' ? 'No DNS records were imported; this rule cannot run.' : status === 'insufficient' ? 'DNS records lack response codes and answers (query-only logging), so names cannot be linked to addresses.' : bursts + ' NXDOMAIN burst(s) found; ' + unlinked + ' had no resolution followed by a connection and are not reported.' + (conns.length ? '' : ' No connection records were imported, so the final step cannot match.') });
    }

    /* ------------------------------------------------ NV-SRC-001 */
    {
      const groups = new Map();
      for (const r of alerts) {
        const key = [r.signature || r.message.slice(0, 120), r.src || '', r.dst || ''].join('|');
        let g = groups.get(key); if (!g) groups.set(key, g = []); g.push(r);
      }
      const order = { high: 0, medium: 1, low: 2, info: 3 };
      let found = 0, capped = 0;
      for (const [key, list] of groups) {
        if (found >= 200) { capped++; continue; }
        list.sort((a, b) => (a.time ?? Infinity) - (b.time ?? Infinity));
        const sev = list.map(r => r.severity).sort((a, b) => order[a] - order[b])[0] || 'info';
        const r0 = list[0], timed = list.filter(r => r.time != null);
        const assets = [];
        if (r0.src) assets.push({ key: r0.src, kind: 'ip', role: 'alert source' });
        if (r0.dst) assets.push({ key: r0.dst, kind: 'ip', role: 'alert destination' });
        if (!r0.src && r0.host) assets.push({ key: 'host:' + r0.host, kind: 'host', role: 'reported host' });
        findings.push(finding('NV-SRC-001', key, {
          title: (r0.signature || r0.message).slice(0, 160),
          summary: list.length + ' source-reported record(s)' + (r0.src ? ' from ' + r0.src : '') + (r0.dst ? ' to ' + r0.dst : '') + '.',
          interpretation: 'The sensor or tool that produced these records flagged them. NEXUS did not evaluate the signature logic.',
          severity: sev, severityBasis: 'Severity is copied from the source record; it is not an independent NEXUS assessment.',
          confidence: 'not assessed', confidenceBasis: ['Source detections are passed through without re-evaluation.'],
          completeness: timed.length === list.length ? 'complete' : 'partial', completenessNotes: timed.length === list.length ? [] : [list.length - timed.length + ' record(s) lack a usable timestamp.'],
          window: timed.length ? { start: timed[0].time, end: timed[timed.length - 1].time } : null,
          thresholds: [{ name: 'Matching source records', threshold: '≥ 1', observed: list.length, met: true }],
          evidenceIds: list.map(r => r.id), assets,
          edges: r0.src && r0.dst ? [{ a: r0.src, b: r0.dst, kind: 'comm', basis: 'Alert records name this source and destination.' }] : [],
          alternatives: ['Signature false positive; review the rule content and the matched traffic.', 'Expected behaviour of authorised tools.'],
          missingContext: ['The packet or payload that matched the signature.', 'The signature definition and its known false-positive rate.'],
          nextSteps: ['Review the signature and the matching payload.', 'Look for related activity from the same addresses.']
        }));
        found++;
      }
      coverage.push({ ruleId: 'NV-SRC-001', version: RULES['NV-SRC-001'].version, title: RULES['NV-SRC-001'].title, status: alerts.length ? 'evaluated' : 'not-applicable', evaluated: alerts.length, excluded: capped ? { 'beyond 200 grouped findings': capped } : {}, findings: found,
        detail: alerts.length ? groups.size + ' signature/source/destination group(s).' : 'No source alerts were imported.' });
    }

    /* ------------------------------------------------ NV-EXEC-001 / NV-SVC-001 */
    {
      const re = /(?:powershell|pwsh)(?:\.exe)?\b.{0,100}\s-(?:enc(?:odedcommand)?|e)\s+[A-Za-z0-9+/=]{12,}/i;
      let found = 0;
      for (const r of textual) {
        if (!re.test(r.message) && !re.test(r.raw || '')) continue;
        const assets = r.host ? [{ key: 'host:' + r.host, kind: 'host', role: 'reported host' }] : r.src ? [{ key: r.src, kind: 'ip', role: 'reported address' }] : [];
        findings.push(finding('NV-EXEC-001', r.id, {
          title: 'Encoded PowerShell command' + (r.host ? ' on ' + r.host : ''), summary: 'A command line in ' + r.source + ' line ' + r.line + ' passes an encoded command to PowerShell.',
          interpretation: 'Encoding can hide script content; administrative tooling also uses it.', severity: 'medium', severityBasis: 'Execution of hidden content is possible; whether it ran is not shown by a text match.',
          confidence: 'low', confidenceBasis: ['A single pattern match in text.'], completeness: r.time != null ? 'complete' : 'partial', completenessNotes: r.time != null ? [] : ['No usable timestamp.'],
          window: r.time != null ? { start: r.time, end: r.time } : null, thresholds: [{ name: 'Pattern', threshold: 'powershell … -enc <base64 ≥12>', observed: 'matched', met: true }],
          evidenceIds: [r.id], assets, edges: [], alternatives: ['Legitimate administrative or deployment scripts.'], missingContext: ['Decoded command content.', 'Process ancestry and whether the command executed.'], nextSteps: ['Decode the argument offline and review it.']
        }));
        found++;
      }
      coverage.push({ ruleId: 'NV-EXEC-001', version: RULES['NV-EXEC-001'].version, title: RULES['NV-EXEC-001'].title, status: textual.length ? 'evaluated' : 'not-applicable', evaluated: textual.length, excluded: {}, findings: found, detail: textual.length ? 'Pattern applied to text, syslog and adapter records.' : 'No text or command-line records were imported.' });
      const ports = RULES['NV-SVC-001'].params.ports;
      let svc = 0;
      for (const r of scans) {
        if (r.extra?.state !== 'open' || !ports.includes(r.port)) continue;
        const ip = r.dst || r.host;
        findings.push(finding('NV-SVC-001', r.id, {
          title: 'Port ' + r.port + ' reachable on ' + ip, summary: 'A scan record reports port ' + r.port + ' open on ' + ip + '.',
          interpretation: 'A sensitive service is reachable in the scanned scope.', severity: 'medium', severityBasis: 'Exposure only; no vulnerability is established.',
          confidence: 'not assessed', confidenceBasis: ['Reachability is reported by the scanner.'], completeness: 'complete', completenessNotes: [],
          window: r.time != null ? { start: r.time, end: r.time } : null, thresholds: [{ name: 'Port in review list', threshold: ports.join(', '), observed: r.port, met: true }],
          evidenceIds: [r.id], assets: ip ? [{ key: ip, kind: 'ip', role: 'scanned host' }] : [], edges: [], alternatives: ['The service is intentionally exposed and hardened.'], missingContext: ['Service version and authentication configuration.'], nextSteps: ['Confirm the service owner and whether exposure is intended.']
        }));
        svc++;
      }
      coverage.push({ ruleId: 'NV-SVC-001', version: RULES['NV-SVC-001'].version, title: RULES['NV-SVC-001'].title, status: scans.length ? 'evaluated' : 'not-applicable', evaluated: scans.length, excluded: {}, findings: svc, detail: scans.length ? 'Open-port scan records checked against the review list.' : 'No scan results were imported.' });
    }

    /* ------------------------------------------------ corroboration */
    const byAsset = new Map();
    for (const f of findings) for (const a of f.assets) { let l = byAsset.get(a.key); if (!l) byAsset.set(a.key, l = []); l.push(f); }
    for (const f of findings) {
      const others = new Set();
      for (const a of f.assets) for (const g of byAsset.get(a.key) || []) if (g !== f) others.add(g);
      f.related = [...others].map(g => g.id);
      if (f.ruleId === 'NV-NET-001') {
        const dst = f.assets.find(a => a.role === 'external destination')?.key;
        const support = [...others].filter(g => (g.ruleId === 'NV-DNS-001' || g.ruleId === 'NV-SRC-001') && g.assets.some(a => a.key === dst));
        if (support.length) {
          f.corroboration = support.map(g => g.ruleId + ' ' + g.id + ' involves ' + dst + '.');
          f.confidence = raise(f.confidence);
          f.confidenceBasis.push('Raised one level: ' + dst + ' also appears in ' + support.map(g => g.ruleId).join(', ') + '.');
          f.severity = 'high'; f.severityBasis = 'Raised: the periodic destination is corroborated by another finding.';
        }
      }
    }
    const sevOrder = { high: 0, medium: 1, low: 2, info: 3 };
    findings.sort((a, b) => sevOrder[a.severity] - sevOrder[b.severity] || (a.window?.start ?? Infinity) - (b.window?.start ?? Infinity));
    return { ruleset: RULESET, findings, coverage, durationMs: Date.now() - started, evaluatedRecords: records.length };
  }

  return { evaluate, RULES, RULESET };
})();
if (typeof module !== 'undefined' && module.exports) module.exports = NVRules;
