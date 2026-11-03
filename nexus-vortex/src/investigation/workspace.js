/* NEXUS VORTEX // INCIDENT RECONSTRUCTION WORKSPACE
   Evidence store → ingest worker → rules → mesh/timeline/explorer → cases.
   Runs inside the application closure; every untrusted string goes through
   esc() or textContent. */
const NV_APP_VERSION = '11.1';
const UTC = {
  full: ms => ms == null || !Number.isFinite(ms) ? 'unknown' : new Date(ms).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
  precise: ms => ms == null || !Number.isFinite(ms) ? 'unknown' : new Date(ms).toISOString().replace('T', ' ').replace('Z', ' UTC'),
  clock: ms => ms == null || !Number.isFinite(ms) ? '--:--:--' : new Date(ms).toISOString().slice(11, 19),
  input: ms => new Date(ms).toISOString().slice(0, 19),
  parseInput: v => { const t = Date.parse(v.length === 16 ? v + ':00Z' : v + 'Z'); return Number.isFinite(t) ? t : null; },
  span(ms) { if (!Number.isFinite(ms)) return '—'; const s = Math.round(ms / 1000); if (s < 120) return s + ' s'; if (s < 7200) return Math.round(s / 60) + ' min'; if (s < 172800) return (s / 3600).toFixed(1) + ' h'; return (s / 86400).toFixed(1) + ' d'; }
};
const QUALITY_LABEL = { 'explicit-zone': 'EXACT / OFFSET', epoch: 'EXACT / EPOCH', 'assumed-zone': 'ASSUMED ZONE', 'assumed-year': 'ASSUMED YEAR + ZONE', 'date-only': 'DATE ONLY', ambiguous: 'AMBIGUOUS DATE', implausible: 'IMPLAUSIBLE', unparseable: 'UNPARSEABLE', missing: 'NO TIMESTAMP', adapter: 'ADAPTER-PARSED', migrated: 'MIGRATED', observed: 'LOCAL CLOCK' };
const EXACT_Q = new Set(['explicit-zone', 'epoch', 'observed']);
const qualityTone = q => EXACT_Q.has(q) ? 'ok' : ['assumed-zone', 'assumed-year', 'date-only', 'adapter', 'migrated'].includes(q) ? 'warn' : 'alert';
const irPill = (text, tone = '') => `<span class="ir-pill" data-tone="${esc(tone)}">${esc(text)}</span>`;
const KIND_LABEL = { internal: 'INTERNAL ADDRESS', external: 'EXTERNAL ADDRESS', domain: 'DNS NAME', account: 'ACCOUNT', host: 'LOGGING HOST' };
const EDGE_LABEL = { comm: 'OBSERVED COMMUNICATION', 'dns-query': 'OBSERVED DNS LOOKUP', 'dns-answer': 'OBSERVED DNS ANSWER', auth: 'OBSERVED AUTHENTICATION', 'auth-target': 'OBSERVED LOGON TARGET', inferred: 'INFERRED ASSOCIATION' };
const accountKeyOf = r => 'user:' + r.user + '@' + (r.host || 'unknown');
function lowerBound(arr, value, key) { let lo = 0, hi = arr.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (arr[mid][key] < value) lo = mid + 1; else hi = mid; } return lo; }
function upperBound(arr, value, key) { let lo = 0, hi = arr.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (arr[mid][key] <= value) lo = mid + 1; else hi = mid; } return lo; }
function fnv(str) { let h = 0x811c9dc5; for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193); } return h >>> 0; }

/* ============================================================== EVIDENCE */
const Evidence = (() => {
  const LIMITS = { records: 150000, rawChars: 160 * 1048576, live: 10000 };
  let records = [], byId = new Map(), rawChars = 0, version = 0, index = null, liveEvicted = 0;
  const listeners = new Set();
  let notifyQueued = false;
  function changed() {
    version++; index = null;
    if (notifyQueued) return;
    notifyQueued = true;
    setTimeout(() => { notifyQueued = false; listeners.forEach(fn => { try { fn(); } catch (e) { console.error(e); } }); }, 0);
  }
  function add(batch) {
    let n = 0;
    for (const r of batch) { if (byId.has(r.id)) continue; records.push(r); byId.set(r.id, r); rawChars += r.raw ? r.raw.length : 0; n++; }
    if (n) changed();
    return n;
  }
  function addLive(batch) {
    add(batch);
    const live = records.filter(r => r.importId === 'live');
    if (live.length <= LIMITS.live) return [];
    const drop = new Set(live.slice(0, live.length - LIMITS.live).map(r => r.id));
    liveEvicted += drop.size;
    records = records.filter(r => { if (!drop.has(r.id)) return true; byId.delete(r.id); rawChars -= r.raw ? r.raw.length : 0; return false; });
    changed();
    return [...drop];
  }
  function annotate(list) { for (const a of list) { const r = byId.get(a.id); if (r) (r.conflicts || (r.conflicts = [])).push(a.conflict); } }
  function duplicates(list) { for (const d of list) { const r = byId.get(d.id); if (!r) continue; const s = r.alsoSeenAt || (r.alsoSeenAt = []); if (s.length < 20) s.push(d.location); r.alsoSeenCount = (r.alsoSeenCount || 0) + 1; } }
  function removeImport(importId) {
    const before = records.length;
    records = records.filter(r => { if (r.importId !== importId) return true; byId.delete(r.id); rawChars -= r.raw ? r.raw.length : 0; return false; });
    if (records.length !== before) changed();
    return before - records.length;
  }
  function clear() { records = []; byId = new Map(); rawChars = 0; liveEvicted = 0; changed(); }
  function getIndex() {
    if (!index) {
      const timed = [], untimed = [];
      for (const r of records) (r.time != null ? timed : untimed).push(r);
      timed.sort((a, b) => a.time - b.time);
      const byReceived = records.slice().sort((a, b) => a.received - b.received || a.line - b.line);
      index = { timed, untimed, byReceived, version };
    }
    return index;
  }
  return {
    LIMITS, add, addLive, annotate, duplicates, removeImport, clear, index: getIndex,
    get: id => byId.get(id), has: id => byId.has(id), all: () => records,
    get count() { return records.length; }, get version() { return version; }, get rawChars() { return rawChars; }, get liveEvicted() { return liveEvicted; },
    capacity: () => Math.max(0, LIMITS.records - records.length),
    onChange: fn => listeners.add(fn)
  };
})();

/* Records from the legacy adapter, the local companion and local sensors. */
function adapterRecord(r, importId, line, origin, format) {
  const raw = typeof r.raw === 'string' ? r.raw : JSON.stringify(r);
  const t = r.time ? Date.parse(r.time) : NaN;
  const type = String(r.type || 'log');
  const kind = ['nmap_port', 'tcp_scan', 'nmap_host'].includes(type) ? 'scan' : /nessus|openvas|trivy|sarif|zap|nuclei/.test(type) ? 'vuln' : type === 'tcp_socket' ? 'conn' : 'text';
  const ip = v => NVCore.normalizeIP(v);
  return {
    id: importId + ':' + line, importId, source: String(r.source || 'adapter'), line, format, origin,
    raw: raw.slice(0, NVCore.RAW_LIMIT), rawSha256: NVCore.sha256Text(raw), rawBytes: NVCore.utf8(raw).length, rawTruncated: raw.length > NVCore.RAW_LIMIT,
    time: Number.isFinite(t) ? t : null, timeQuality: Number.isFinite(t) ? 'adapter' : 'missing', timeText: r.time || null,
    timeNote: Number.isFinite(t) ? 'Parsed by the legacy adapter with the browser Date parser; zone handling is not verified.' : null,
    received: r.received ? Date.parse(r.received) || Date.now() : Date.now(), kind,
    src: ip(r.src), srcPort: null, dst: ip(r.dst), port: NVCore.normalizePort(r.port) ?? null, proto: null, host: r.host ? String(r.host).slice(0, 253) : null, user: null,
    outcome: null, authLayer: null, authMethod: null, repeat: 1, query: null, qtype: null, rcode: null, answers: null,
    signature: null, severity: ['high', 'medium', 'low', 'info'].includes(r.severity) ? r.severity : 'info', message: String(r.message || '').slice(0, 600),
    uid: null, conflicts: null, notes: ['Imported through the legacy adapter; per-record rejections and duplicates are not reported for this path.'],
    extra: { state: r.fields?.state ?? null, adapterType: type }
  };
}

/* ============================================================== INVESTIGATION STATE */
const Investigation = (() => {
  const st = { findings: [], coverage: [], ruleset: '', rulesMs: 0, rulesAt: null, rulesRecords: 0, rulesPending: false,
    axis: 'event', window: null, playhead: null, includeUnknown: false,
    finding: null, asset: null, edge: null, focusKeys: null, focusLabel: '' };
  const listeners = new Set();
  let visibleCache = null, graphCache = null;
  function emit(what) { visibleCache = null; graphCache = null; listeners.forEach(fn => { try { fn(what); } catch (e) { console.error(e); } }); }
  Evidence.onChange(() => emit('evidence'));
  const key = () => st.axis === 'event' ? 'time' : 'received';
  function series() { const ix = Evidence.index(); return st.axis === 'event' ? ix.timed : ix.byReceived; }
  function bounds() { const s = series(), k = key(); return s.length ? { min: s[0][k], max: s[s.length - 1][k] } : null; }
  function windowRange() {
    const b = bounds(); if (!b) return null;
    const w = st.window ? { start: Math.max(b.min, Math.min(st.window.start, b.max)), end: Math.min(b.max, Math.max(st.window.end, b.min)) } : { start: b.min, end: b.max };
    if (w.end < w.start) w.end = w.start;
    const end = st.playhead != null ? Math.max(w.start, Math.min(st.playhead, w.end)) : w.end;
    return { start: w.start, end, windowEnd: w.end, full: !st.window, bounds: b };
  }
  function visible() {
    if (visibleCache && visibleCache.version === Evidence.version) return visibleCache.list;
    const ix = Evidence.index(), w = windowRange(), s = series(), k = key();
    let list = w ? s.slice(lowerBound(s, w.start, k), upperBound(s, w.end, k)) : [];
    if (st.axis === 'event' && st.includeUnknown) list = list.concat(ix.untimed);
    visibleCache = { version: Evidence.version, list };
    return list;
  }
  function findingInWindow(f) {
    const w = windowRange();
    if (!w || w.full && st.playhead == null) return true;
    if (!f.window) return st.includeUnknown;
    return f.window.end >= w.start && f.window.start <= w.end;
  }
  function graph() {
    if (graphCache && graphCache.version === Evidence.version) return graphCache.g;
    const g = buildGraph(visible(), st.findings);
    graphCache = { version: Evidence.version, g };
    return g;
  }
  function setFindings(m) {
    st.findings = m.findings; st.coverage = m.coverage; st.ruleset = m.ruleset; st.rulesMs = m.durationMs; st.rulesAt = Date.now(); st.rulesRecords = m.evaluatedRecords; st.rulesPending = false;
    if (st.finding && !st.findings.some(f => f.id === st.finding)) { st.finding = null; st.focusKeys = null; }
    emit('findings');
  }
  function focusFinding(f) {
    st.finding = f ? f.id : null; st.asset = null; st.edge = null; st.pick = f ? 'finding' : null;
    st.focusKeys = f ? new Set(f.assets.map(a => a.key)) : null; st.focusLabel = f ? f.ruleId + ' ' + f.id : '';
    emit('selection');
  }
  return {
    st, on: fn => listeners.add(fn), emit, bounds, windowRange, visible, graph, findingInWindow, setFindings,
    finding: () => st.findings.find(f => f.id === st.finding) || null,
    selectFinding(id) { focusFinding(st.findings.find(f => f.id === id) || null); },
    selectAsset(k) { st.asset = k; st.edge = null; st.pick = k ? 'asset' : null; if (!st.finding) { st.focusKeys = k ? new Set([k]) : null; st.focusLabel = k ? 'asset ' + k.replace(/^(dns|user|host):/, '') : ''; } emit('selection'); },
    selectEdge(k) { st.edge = k; st.asset = null; st.pick = k ? 'edge' : null; emit('selection'); },
    pickSensor() { st.asset = null; st.edge = null; st.pick = 'sensor'; emit('selection'); },
    focusKeys(keys, label) { st.finding = null; st.asset = null; st.edge = null; st.pick = null; st.focusKeys = keys && keys.size ? keys : null; st.focusLabel = label || ''; emit('selection'); },
    clearSelection() { st.finding = null; st.asset = null; st.edge = null; st.pick = null; st.focusKeys = null; st.focusLabel = ''; emit('selection'); },
    setWindow(start, end) { if (start == null || end == null) st.window = null; else st.window = { start: Math.min(start, end), end: Math.max(start, end) }; st.playhead = null; emit('window'); },
    setPlayhead(t) { st.playhead = t; emit('window'); },
    setAxis(a) { st.axis = a === 'ingest' ? 'ingest' : 'event'; st.window = null; st.playhead = null; emit('window'); },
    setIncludeUnknown(v) { st.includeUnknown = !!v; emit('window'); }
  };
})();

/* Asset/relationship graph for the visible records. Every edge records the
   kind of evidence that created it; inferred edges come only from findings. */
function buildGraph(list, findings) {
  const nodes = new Map(), edges = new Map();
  function node(k, kind, label) {
    let n = nodes.get(k);
    if (!n) nodes.set(k, n = { key: k, kind, label, count: 0, first: Infinity, last: -Infinity, ids: [] });
    return n;
  }
  function touch(n, r) { n.count++; const t = r.time ?? r.received; if (t < n.first) n.first = t; if (t > n.last) n.last = t; if (n.ids.length < 400) n.ids.push(r.id); }
  function ipNode(ip, r) { const n = node(ip, NVCore.isInternal(ip) ? 'internal' : 'external', ip); touch(n, r); return n; }
  function edge(a, b, kind, r, detail) {
    const k = kind + '|' + a + '|' + b;
    let e = edges.get(k);
    if (!e) edges.set(k, e = { key: k, a, b, kind, count: 0, first: Infinity, last: -Infinity, ids: [], detail: new Map() });
    e.count++; const t = r.time ?? r.received; if (t < e.first) e.first = t; if (t > e.last) e.last = t;
    if (e.ids.length < 400) e.ids.push(r.id);
    if (detail) e.detail.set(detail, (e.detail.get(detail) || 0) + 1);
  }
  for (const r of list) {
    if (r.kind === 'dns' && r.src && r.query) {
      ipNode(r.src, r);
      const d = node('dns:' + r.query, 'domain', r.query); touch(d, r);
      edge(r.src, d.key, 'dns-query', r, r.rcode || 'query');
      if (r.answers) for (const ip of r.answers) { ipNode(ip, r); edge(d.key, ip, 'dns-answer', r, r.qtype || 'A'); }
    } else if ((r.kind === 'conn' || r.kind === 'http' || r.kind === 'tls' || r.kind === 'alert' || r.kind === 'ssh') && r.src && r.dst) {
      ipNode(r.src, r); ipNode(r.dst, r);
      edge(r.src, r.dst, 'comm', r, r.kind + (r.port != null ? ':' + r.port : ''));
    } else if (r.kind === 'auth' && r.user) {
      const a = node(accountKeyOf(r), 'account', r.user + ' @ ' + (r.host || 'unknown host')); touch(a, r);
      if (r.src) { ipNode(r.src, r); edge(r.src, a.key, 'auth', r, r.outcome || 'event'); }
      if (r.host) { const h = node('host:' + r.host, 'host', r.host); touch(h, r); edge(a.key, h.key, 'auth-target', r, r.outcome || 'event'); }
    } else {
      if (r.src) ipNode(r.src, r);
      if (r.dst && r.dst !== r.src) ipNode(r.dst, r);
      if (r.host && !r.src) touch(node('host:' + r.host, 'host', r.host), r);
    }
  }
  for (const f of findings) for (const e of f.edges || []) {
    if (e.kind !== 'inferred' || !nodes.has(e.a) || !nodes.has(e.b)) continue;
    const k = 'inferred|' + e.a + '|' + e.b;
    if (!edges.has(k)) edges.set(k, { key: k, a: e.a, b: e.b, kind: 'inferred', count: 1, first: f.window?.start ?? NaN, last: f.window?.end ?? NaN, ids: f.evidenceIds.slice(0, 400), detail: new Map(), basis: e.basis, findingId: f.id });
  }
  return { nodes, edges };
}
function edgeBasis(e, g) {
  if (e.basis) return e.basis;
  const label = k => g.nodes.get(k)?.label || k;
  const details = [...e.detail].sort((a, b) => b[1] - a[1]).slice(0, 4).map(([k, v]) => v + '× ' + k).join(', ');
  if (e.kind === 'comm') return e.count + ' record(s) with ' + label(e.a) + ' as source and ' + label(e.b) + ' as destination (' + details + '). Direction is as recorded by the sensor.';
  if (e.kind === 'dns-query') return e.count + ' DNS record(s) show ' + label(e.a) + ' looking up ' + label(e.b) + ' (' + details + ').';
  if (e.kind === 'dns-answer') return e.count + ' DNS response(s) resolved ' + label(e.a) + ' to ' + label(e.b) + '.';
  if (e.kind === 'auth') return e.count + ' authentication record(s) name source ' + label(e.a) + ' and account ' + label(e.b) + ' (' + details + ').';
  if (e.kind === 'auth-target') return e.count + ' authentication record(s) for ' + label(e.a) + ' were logged by ' + label(e.b) + ' (' + details + ').';
  return e.count + ' record(s).';
}

/* ============================================================== MESH PROJECTION */
const MeshBridge = (() => {
  const MAX_NODES = 120, MAX_EDGES = 360;
  const RING = { internal: [0.62, 0.42], external: [1.02, 0.16], domain: [1.34, 0.22], account: [0.5, 0.0], host: [0.42, 0.0] };
  let last = { shown: 0, total: 0, edgesShown: 0, edgesTotal: 0 }, timer = null;
  function position(k, kind) {
    const h = fnv(k), u = (h & 0xffff) / 0xffff, v = (h >>> 16) / 0xffff;
    const a = u * Math.PI * 2;
    if (kind === 'internal') { const y = (v - 0.5) * 2 * 0.62, r = Math.sqrt(Math.max(0, 0.62 * 0.62 - y * y)); return [Math.cos(a) * r, y, Math.sin(a) * r]; }
    if (kind === 'account') return [Math.cos(a) * 0.48, -0.86 - v * 0.12, Math.sin(a) * 0.48];
    if (kind === 'host') return [Math.cos(a) * 0.3, -0.98, Math.sin(a) * 0.3];
    const [radius, spread] = RING[kind] || RING.external;
    return [Math.cos(a) * radius, (v - 0.5) * spread, Math.sin(a) * radius];
  }
  function sync() {
    if (typeof MeshModel === 'undefined') return;
    const g = Investigation.graph(), st = Investigation.st, f = Investigation.finding();
    const focus = st.focusKeys;
    const findingEdges = new Set((f?.edges || []).map(e => e.kind + '|' + e.a + '|' + e.b));
    const all = [...g.nodes.values()];
    const neighbours = new Set();
    if (st.asset) for (const e of g.edges.values()) { if (e.a === st.asset) neighbours.add(e.b); if (e.b === st.asset) neighbours.add(e.a); }
    const rank = n => (focus?.has(n.key) ? 1e12 : 0) + (n.key === st.asset ? 1e11 : 0) + (neighbours.has(n.key) ? 1e10 : 0) + n.count;
    all.sort((a, b) => rank(b) - rank(a));
    const shown = all.slice(0, MAX_NODES);
    const keys = new Set(shown.map(n => n.key));
    const maxCount = Math.max(1, ...shown.map(n => n.count));
    const nodeSpec = shown.map(n => ({ key: n.key, label: n.label, kind: n.kind, pos: position(n.key, n.kind), count: n.count,
      weight: Math.round(8 + 60 * Math.log1p(n.count) / Math.log1p(maxCount)), focus: !!(focus?.has(n.key)) || n.key === st.asset, dim: !!focus && !focus.has(n.key) && n.key !== st.asset && !neighbours.has(n.key) }));
    const candidate = [...g.edges.values()].filter(e => keys.has(e.a) && keys.has(e.b));
    const edgeFocus = e => findingEdges.has(e.kind + '|' + e.a + '|' + e.b) || (st.asset && (e.a === st.asset || e.b === st.asset)) || (focus && !f && focus.has(e.a) && focus.has(e.b));
    candidate.sort((a, b) => (edgeFocus(b) - edgeFocus(a)) || (b.kind === 'inferred') - (a.kind === 'inferred') || b.count - a.count);
    const edgeSpec = candidate.slice(0, MAX_EDGES).map(e => ({ key: e.key, a: e.a, b: e.b, kind: e.kind, count: e.count, focus: !!edgeFocus(e), dim: !!focus && !edgeFocus(e), selected: e.key === st.edge }));
    last = { shown: shown.length, total: g.nodes.size, edgesShown: edgeSpec.length, edgesTotal: g.edges.size };
    MeshModel.syncEvidence({ nodes: nodeSpec, edges: edgeSpec, selectedAsset: st.asset, selectedEdge: st.edge });
  }
  function schedule(delay = 60) { if (timer) return; timer = setTimeout(() => { timer = null; sync(); }, delay); }
  return { sync, schedule, get stats() { return last; }, MAX_NODES, MAX_EDGES };
})();

/* ============================================================== INGEST BRIDGE */
const Ingest = (() => {
  const imports = new Map();
  let engine = null, engineMode = 'starting', engineNote = '', jobSeq = 0, current = null, queue = [], workerURL = null;
  const listeners = new Set();
  const emit = what => listeners.forEach(fn => { try { fn(what); } catch (e) { console.error(e); } });
  const newImportId = () => 'I' + Date.now().toString(36).slice(-4) + (++jobSeq).toString(36);
  function start() {
    try {
      const src = document.getElementById('nvIngestWorker')?.textContent;
      if (!src || typeof Worker === 'undefined') throw new Error('Web Workers are unavailable in this context.');
      workerURL = URL.createObjectURL(new Blob([src], { type: 'text/javascript' }));
      const w = new Worker(workerURL);
      w.onmessage = e => onMessage(e.data);
      w.onerror = e => { e.preventDefault?.(); fallback('The ingest worker stopped: ' + (e.message || 'unknown error') + '.'); };
      engine = { post: m => w.postMessage(m), terminate: () => w.terminate() };
      engineMode = 'worker';
    } catch (e) { fallback(e.message); }
  }
  function fallback(reason) {
    try { engine?.terminate?.(); } catch {}
    const eng = NVIngestEngine.create(m => setTimeout(() => onMessage(m), 0), { yieldFn: () => new Promise(r => setTimeout(r, 0)) });
    engine = { post: m => eng.handle(m), terminate() {} };
    engineMode = 'main-thread'; engineNote = reason + ' Imports run on the page thread in chunks; the interface may stutter on large files.';
    if (current) { const job = current; current = null; finish(job.entry, { ...(job.entry.receipt || {}), status: 'failed', error: reason }); }
    emit('engine');
  }
  function options() {
    return { zoneOffsetMinutes: Number($('#irZone')?.value || 0), syslogYear: Number($('#irYear')?.value) || new Date().getUTCFullYear(), slashOrder: $('#irSlash')?.value || 'reject' };
  }
  function enqueue(files, { format = $('#irFormat')?.value || 'auto', label = null } = {}) {
    for (const file of files) queue.push({ file, format, label });
    if (!current) next();
    emit('queue');
  }
  async function next() {
    const item = queue.shift();
    if (!item) { current = null; emit('idle'); return; }
    const { file, format, label } = item;
    const importId = newImportId();
    const entry = { importId, fileName: label || file.name, fileSize: file.size, lastModified: file.lastModified, file, format, status: 'running', receipt: null, fileSha256: null, hashError: null, startedAt: Date.now(), synthetic: !!label?.startsWith('synthetic/') };
    imports.set(importId, entry);
    current = { entry, jobId: ++jobSeq, progress: null, t0: performance.now() };
    emit('start');
    hashSource(entry);
    try {
      if (format === 'auto' && await isLegacy(file)) { await legacyImport(entry); return; }
    } catch (e) { finish(entry, { status: 'failed', error: e.message, fileName: entry.fileName, accepted: 0, rejected: 0 }); return; }
    engine.post({ type: 'import', jobId: current.jobId, importId, file, fileName: entry.fileName, format, options: options(), maxRecords: Evidence.capacity(), paceMs: window.__NV_IMPORT_PACE || 0 });
  }
  async function hashSource(entry) {
    try { const out = await Defense.hashFile(entry.file, ['SHA-256']); entry.fileSha256 = out['SHA-256']; }
    catch (e) { entry.hashError = e.message; }
    emit('hash');
  }
  async function isLegacy(file) {
    const head = (await file.slice(0, 4096).text()).replace(/^\ufeff/, '').trimStart();
    if (head.startsWith('<')) return true;
    return head.startsWith('{') && /"(Results|runs|site|investigation)"\s*:/.test(head) && file.size <= 20 * 1048576;
  }
  async function legacyImport(entry) {
    if (entry.file.size > 20 * 1048576) throw new Error('Legacy adapter files are limited to 20 MiB.');
    const text = await entry.file.text();
    let parsed;
    try { parsed = Operations.parse(text, entry.fileName); } catch (e) { finish(entry, { status: 'failed', error: 'Legacy adapter: ' + e.message, fileName: entry.fileName, accepted: 0, rejected: 0 }); return; }
    const cap = Evidence.capacity();
    const records = parsed.slice(0, cap).map((r, i) => adapterRecord({ ...r, source: entry.fileName }, entry.importId, i + 1, 'IMPORT', 'legacy-adapter'));
    Evidence.add(records);
    engine.post({ type: 'add-rows', importId: entry.importId, rows: records });
    const tq = {}; for (const r of records) tq[r.timeQuality] = (tq[r.timeQuality] || 0) + 1;
    finish(entry, {
      importId: entry.importId, fileName: entry.fileName, fileSize: entry.fileSize, format: 'legacy-adapter', formatLabel: 'Legacy adapter (Nmap / Nessus / OpenVAS / Trivy / SARIF / ZAP / JSON)',
      detection: { method: 'automatic', reason: 'XML or single-document JSON report recognised by the pre-existing adapter.' },
      status: parsed.length > cap ? 'limit' : 'complete', accepted: records.length, rejected: null, duplicates: { withinFile: null, acrossImports: null }, linesRead: null, bytesRead: entry.fileSize,
      timeQuality: tq, conflicts: { timestamp: null, identity: null }, rawTruncated: records.filter(r => r.rawTruncated).length, rejectReasons: {}, rejectSamples: [], rejectedLines: [], duplicateSamples: [], conflictSamples: [],
      limit: parsed.length > cap ? { atLine: cap + 1, reason: 'Session retention limit reached; ' + (parsed.length - cap) + ' adapter records were not imported.' } : null,
      assumptions: ['Timestamps were parsed by the browser Date parser; values without a zone follow this browser’s local time zone.'],
      notes: ['This adapter predates the verified parsers: it does not report rejected or duplicate records, and it is outside the automated verification suite. Each adapter record is capped at 10,000 per file.'],
      startedAt: new Date(entry.startedAt).toISOString(), finishedAt: new Date().toISOString(), durationMs: Date.now() - entry.startedAt
    });
  }
  function finish(entry, receipt) {
    entry.receipt = receipt; entry.status = receipt.status;
    if (['cancelled', 'failed'].includes(receipt.status)) { const n = Evidence.removeImport(entry.importId); receipt.rolledBack = n; }
    if (receipt.status !== 'unrecognized') entry.file = null;
    if (current?.entry === entry) current = null;
    emit('done');
    next();
  }
  function onMessage(m) {
    if (m.type === 'progress') { if (current && m.jobId === current.jobId) { current.progress = m; emit('progress'); } return; }
    if (m.type === 'batch') { Evidence.add(m.records); if (m.annotations.length) Evidence.annotate(m.annotations); if (m.duplicates.length) Evidence.duplicates(m.duplicates); return; }
    if (m.type === 'done') { const entry = imports.get(m.importId); if (entry) finish(entry, m.receipt); return; }
    if (m.type === 'rules') { Investigation.setFindings(m); emit('rules'); }
  }
  function cancel() { if (current) { engine.post({ type: 'cancel', jobId: current.jobId }); current.cancelRequestedAt = performance.now(); emit('cancelling'); } }
  async function remove(importId) {
    const entry = imports.get(importId); if (!entry) return;
    const n = Evidence.removeImport(importId);
    engine.post({ type: 'remove-import', importId });
    entry.status = 'removed'; entry.removedRecords = n; entry.removedAt = new Date().toISOString();
    emit('removed');
  }
  function retryAsText(importId) {
    const entry = imports.get(importId); if (!entry?.file) return;
    enqueue([entry.file], { format: 'text', label: entry.fileName });
  }
  function addAdapterRows(importId, records, replace = false) { engine?.post({ type: 'add-rows', importId, rows: records, replace }); }
  function clearAll() { queue = []; if (current) cancel(); Evidence.clear(); engine.post({ type: 'clear' }); for (const e of imports.values()) if (e.status !== 'running') { e.status = e.status === 'removed' ? 'removed' : 'cleared'; } emit('cleared'); }
  return {
    start, enqueue, cancel, remove, retryAsText, addAdapterRows, clearAll, options, imports,
    get current() { return current; }, get queued() { return queue.length; }, get mode() { return engineMode; }, get note() { return engineNote; },
    on: fn => listeners.add(fn), evaluate: () => engine?.post({ type: 'evaluate' })
  };
})();

/* ============================================================== CASE STORAGE */
const CaseStore = (() => {
  const DB = 'nexus-vortex-cases', LS_KEY = 'nexus-vortex-cases-v2', V1_KEY = 'nexus-investigations-v1';
  let db = null, backend = 'none', error = '', note = '', ready = null;
  const cases = new Map();
  const listeners = new Set();
  const emit = () => listeners.forEach(fn => { try { fn(); } catch (e) { console.error(e); } });
  function describe(e) {
    const name = e?.name || '';
    if (name === 'QuotaExceededError' || /quota/i.test(e?.message || '')) return 'Browser storage is full (quota exceeded).';
    if (name === 'SecurityError') return 'Browser storage is blocked for this page (security settings or private mode).';
    if (name === 'InvalidStateError') return 'Browser storage was closed or is unavailable.';
    return (e?.message || String(e)) || 'Unknown storage error.';
  }
  function openDB() {
    return new Promise((resolve, reject) => {
      let req;
      try { req = indexedDB.open(DB, 1); } catch (e) { reject(e); return; }
      req.onupgradeneeded = () => { const d = req.result; if (!d.objectStoreNames.contains('cases')) d.createObjectStore('cases', { keyPath: 'id' }); if (!d.objectStoreNames.contains('meta')) d.createObjectStore('meta', { keyPath: 'key' }); };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
      req.onblocked = () => reject(new Error('Storage upgrade blocked by another open tab.'));
    });
  }
  function tx(store, mode, fn) {
    return new Promise((resolve, reject) => {
      let t, result;
      try { t = db.transaction(store, mode); const r = fn(t.objectStore(store)); if (r) r.onsuccess = () => { result = r.result; }; }
      catch (e) { reject(e); return; }
      t.oncomplete = () => resolve(result);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error || new Error('Storage transaction aborted.'));
    });
  }
  async function migrate() {
    let meta = null;
    try { meta = await tx('meta', 'readonly', s => s.get('migration-v1')); } catch {}
    if (meta) return;
    let raw = null;
    try { raw = localStorage.getItem(V1_KEY); } catch {}
    let migrated = 0, failed = 0;
    if (raw) {
      let list = [];
      try { list = JSON.parse(raw); if (!Array.isArray(list)) throw new Error(); } catch { failed = -1; }
      for (const old of Array.isArray(list) ? list : []) {
        try { const c = NVCases.normalizeCase(old); if (!cases.has(c.id)) { await tx('cases', 'readwrite', s => s.put(c)); cases.set(c.id, c); migrated++; } } catch { failed++; }
      }
    }
    await tx('meta', 'readwrite', s => s.put({ key: 'migration-v1', at: new Date().toISOString(), migrated, failed }));
    if (migrated || failed) note = 'Migrated ' + migrated + ' investigation(s) from the v1 store' + (failed ? '; ' + (failed < 0 ? 'the v1 store was unreadable' : failed + ' could not be converted') : '') + '. The original v1 data was left in place.';
  }
  async function init() {
    try {
      if (typeof indexedDB === 'undefined') throw new Error('IndexedDB is unavailable.');
      db = await openDB();
      db.onversionchange = () => { db.close(); db = null; backend = 'none'; error = 'Case storage was closed by another tab; reload to continue saving.'; emit(); };
      const list = await tx('cases', 'readonly', s => s.getAll());
      for (const c of list || []) { try { cases.set(c.id, NVCases.normalizeCase(c)); } catch (e) { error = 'A stored case could not be read (' + e.message + '); it was left untouched.'; } }
      backend = 'indexeddb';
      await migrate();
    } catch (e) {
      db = null;
      error = 'IndexedDB unavailable: ' + describe(e);
      try {
        const raw = localStorage.getItem(LS_KEY);
        for (const c of raw ? JSON.parse(raw) : []) cases.set(c.id, NVCases.normalizeCase(c));
        localStorage.setItem(LS_KEY + '-probe', '1'); localStorage.removeItem(LS_KEY + '-probe');
        backend = 'localstorage'; error += ' Using localStorage instead (smaller quota).';
      } catch (e2) { backend = 'memory'; error += ' localStorage also failed: ' + describe(e2) + ' Cases will be lost when this tab closes; export them.'; }
    }
    emit();
  }
  async function put(c) {
    const copy = JSON.parse(JSON.stringify(c));
    if (backend === 'indexeddb') await tx('cases', 'readwrite', s => s.put(copy));
    else if (backend === 'localstorage') { const all = [...cases.values()].filter(x => x.id !== c.id).concat([copy]); localStorage.setItem(LS_KEY, JSON.stringify(all)); }
    else throw new Error('No persistent storage is available in this browser context.');
    cases.set(c.id, copy);
    error = '';
    emit();
  }
  async function remove(id) {
    if (backend === 'indexeddb') await tx('cases', 'readwrite', s => s.delete(id));
    else if (backend === 'localstorage') localStorage.setItem(LS_KEY, JSON.stringify([...cases.values()].filter(x => x.id !== id)));
    cases.delete(id);
    emit();
  }
  return {
    init: () => ready || (ready = init()), put: async c => { try { await put(c); } catch (e) { error = 'Not saved: ' + describe(e); emit(); throw new Error(error); } },
    remove: async id => { try { await remove(id); } catch (e) { error = 'Not deleted: ' + describe(e); emit(); throw new Error(error); } },
    list: () => [...cases.values()].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)), get: id => cases.get(id),
    get backend() { return backend; }, get error() { return error; }, get note() { return note; }, on: fn => listeners.add(fn), describe
  };
})();

/* ============================================================== TIMELINE */
const Timeline = (() => {
  const instances = new Set();
  let playTimer = null, playStarted = 0, playFrom = 0, playSpeed = 1, raf = null;
  const PLAY_MS = 24000;
  function create(host, compact) {
    host.innerHTML = `<div class="ir-tl${compact ? ' ir-tl--compact' : ''}">
      <div class="ir-tl__head">
        <div class="ir-tl__axis" role="group" aria-label="Time axis"><button class="chip" data-tl-axis="event" aria-pressed="true">EVENT TIME</button><button class="chip" data-tl-axis="ingest" aria-pressed="false">INGESTION TIME</button></div>
        <span class="ir-tl__label" data-tl-label aria-live="polite"></span>
        <label class="ir-check" data-tl-unknown-wrap><input type="checkbox" data-tl-unknown> include <b data-tl-unknown-count>0</b> unknown-time</label>
      </div>
      <div class="ir-tl__stage" data-tl-stage><canvas data-tl-canvas role="img" aria-label="Histogram of record times. Drag to select an investigation window; click to move the playhead."></canvas></div>
      <div class="ir-tl__controls">
        <button class="btn btn--sm" data-tl-play aria-pressed="false"><svg class="icon"><use href="#i-play"/></svg> <span>PLAY</span></button>
        <label class="ir-tl__speed">SPEED<select data-tl-speed><option value="0.5">0.5×</option><option value="1" selected>1×</option><option value="3">3×</option><option value="8">8×</option></select></label>
        <input type="range" class="range ir-tl__scrub" data-tl-scrub min="0" max="1000" step="1" value="1000" aria-label="Playhead within the investigation window">
        <button class="btn btn--sm" data-tl-reset>FULL RANGE</button>
      </div>
      ${compact ? '' : `<div class="ir-tl__inputs"><label>WINDOW START (UTC)<input type="datetime-local" step="1" data-tl-start></label><label>WINDOW END (UTC)<input type="datetime-local" step="1" data-tl-end></label><button class="btn btn--sm" data-tl-apply>APPLY WINDOW</button></div>`}
      <p class="ir-tl__note">Event time is the source timestamp after the import assumptions; ingestion time is when this browser read the record. Bands mark finding windows. Ordering is not proof of causation, and clocks on different sources can disagree.</p>
    </div>`;
    const inst = { host, compact, canvas: host.querySelector('[data-tl-canvas]'), stage: host.querySelector('[data-tl-stage]'), drag: null, bins: null };
    const ro = new ResizeObserver(() => draw(inst)); ro.observe(inst.stage); inst.ro = ro;
    bind(inst);
    instances.add(inst);
    draw(inst);
    return inst;
  }
  function geometry(inst) { const w = inst.stage.clientWidth || 600, h = inst.stage.clientHeight || 120; return { w, h, pad: 8 }; }
  function xToTime(inst, x) { const b = Investigation.bounds(); if (!b) return null; const { w, pad } = geometry(inst); const span = Math.max(1, b.max - b.min); return b.min + clamp((x - pad) / (w - pad * 2), 0, 1) * span; }
  function timeToX(inst, t) { const b = Investigation.bounds(); const { w, pad } = geometry(inst); const span = Math.max(1, b.max - b.min); return pad + (t - b.min) / span * (w - pad * 2); }
  function bind(inst) {
    const h = inst.host;
    h.addEventListener('click', e => {
      const axis = e.target.closest('[data-tl-axis]');
      if (axis) { stop(); Investigation.setAxis(axis.dataset.tlAxis); return; }
      if (e.target.closest('[data-tl-play]')) { playing() ? stop() : play(); return; }
      if (e.target.closest('[data-tl-reset]')) { stop(); Investigation.setWindow(null, null); return; }
      if (e.target.closest('[data-tl-apply]')) {
        const s = UTC.parseInput(h.querySelector('[data-tl-start]').value), en = UTC.parseInput(h.querySelector('[data-tl-end]').value);
        if (s == null || en == null) { SecurityFabric.notify('Enter both window bounds as UTC date and time.'); return; }
        stop(); Investigation.setWindow(s, en);
      }
    });
    h.querySelector('[data-tl-unknown]').addEventListener('change', e => Investigation.setIncludeUnknown(e.target.checked));
    h.querySelector('[data-tl-speed]').addEventListener('change', e => { playSpeed = Number(e.target.value) || 1; if (playing()) { const w = Investigation.windowRange(); playFrom = w.end; playStarted = performance.now(); } });
    h.querySelector('[data-tl-scrub]').addEventListener('input', e => {
      stop();
      const w = Investigation.windowRange(); if (!w) return;
      const v = Number(e.target.value) / 1000;
      Investigation.setPlayhead(v >= 1 ? null : w.start + v * (w.windowEnd - w.start));
    });
    const c = inst.canvas;
    c.addEventListener('pointerdown', e => {
      if (!Investigation.bounds()) return;
      const r = c.getBoundingClientRect();
      inst.drag = { x0: e.clientX - r.left, x1: e.clientX - r.left };
      c.setPointerCapture?.(e.pointerId);
    });
    c.addEventListener('pointermove', e => { if (!inst.drag) return; const r = c.getBoundingClientRect(); inst.drag.x1 = e.clientX - r.left; draw(inst); });
    const end = e => {
      if (!inst.drag) return;
      const { x0, x1 } = inst.drag; inst.drag = null;
      stop();
      if (Math.abs(x1 - x0) < 4) {
        const t = xToTime(inst, x1), w = Investigation.windowRange();
        if (t == null || !w) return;
        if (t < w.start || t > w.windowEnd) Investigation.setWindow(null, null);
        Investigation.setPlayhead(t >= Investigation.windowRange().windowEnd ? null : t);
      } else Investigation.setWindow(xToTime(inst, Math.min(x0, x1)), xToTime(inst, Math.max(x0, x1)));
    };
    c.addEventListener('pointerup', end); c.addEventListener('pointercancel', () => { inst.drag = null; draw(inst); });
    c.addEventListener('dblclick', () => { stop(); Investigation.setWindow(null, null); });
  }
  function histogram(inst, w) {
    const b = Investigation.bounds();
    const st = Investigation.st;
    const ix = Evidence.index(), s = st.axis === 'event' ? ix.timed : ix.byReceived, k = st.axis === 'event' ? 'time' : 'received';
    const n = Math.max(20, Math.min(240, Math.floor(w / 4)));
    const counts = new Array(n).fill(0);
    if (!b || !s.length) return { counts, n, b };
    const span = Math.max(1, b.max - b.min);
    let lo = 0;
    for (let i = 0; i < n; i++) { const edge = i === n - 1 ? b.max : b.min + span * (i + 1) / n; const hi = upperBound(s, edge, k); counts[i] = hi - lo; lo = hi; }
    return { counts, n, b };
  }
  function draw(inst) {
    const { w, h, pad } = geometry(inst);
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const c = inst.canvas;
    if (c.width !== Math.round(w * dpr) || c.height !== Math.round(h * dpr)) { c.width = Math.round(w * dpr); c.height = Math.round(h * dpr); }
    const ctx = c.getContext('2d'); ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, w, h);
    const st = Investigation.st, win = Investigation.windowRange();
    const { counts, n, b } = histogram(inst, w);
    ctx.strokeStyle = 'rgba(0,240,255,.08)'; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) { const y = pad + (h - pad * 2 - 14) * i / 4; ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(w - pad, y); ctx.stroke(); }
    if (!b) { ctx.fillStyle = 'rgba(138,169,187,.8)'; ctx.font = '12px ui-monospace, monospace'; ctx.fillText(Evidence.count ? 'NO RECORDS WITH USABLE EVENT TIMES — SEE UNKNOWN-TIME BUCKET' : 'IMPORT EVIDENCE TO BUILD THE TIMELINE', pad + 4, h / 2); syncControls(inst, null); return; }
    const max = Math.max(1, ...counts), bw = (w - pad * 2) / n, base = h - 16;
    if (st.axis === 'event') for (const f of st.findings) {
      if (!f.window) continue;
      const x0 = timeToX(inst, f.window.start), x1 = Math.max(x0 + 2, timeToX(inst, f.window.end));
      const sel = f.id === st.finding;
      ctx.fillStyle = sel ? 'rgba(255,43,214,.26)' : f.severity === 'high' ? 'rgba(255,43,214,.09)' : 'rgba(255,182,72,.07)';
      ctx.fillRect(x0, pad, x1 - x0, base - pad);
      if (sel) { ctx.strokeStyle = 'rgba(255,43,214,.85)'; ctx.strokeRect(x0 + .5, pad + .5, x1 - x0 - 1, base - pad - 1); }
    }
    for (let i = 0; i < n; i++) {
      if (!counts[i]) continue;
      const x = pad + i * bw, bh = Math.max(1.5, (base - pad) * Math.sqrt(counts[i] / max));
      const t = b.min + (b.max - b.min) * (i + .5) / n;
      const inside = win && t >= win.start && t <= win.end;
      ctx.fillStyle = inside ? 'rgba(0,240,255,.85)' : 'rgba(0,240,255,.22)';
      ctx.fillRect(x + .5, base - bh, Math.max(1, bw - 1), bh);
    }
    if (win && !win.full) {
      const x0 = timeToX(inst, win.start), x1 = timeToX(inst, win.windowEnd);
      ctx.fillStyle = 'rgba(1,2,4,.55)'; ctx.fillRect(pad, pad, x0 - pad, base - pad); ctx.fillRect(x1, pad, w - pad - x1, base - pad);
      ctx.strokeStyle = 'rgba(154,252,255,.9)'; ctx.beginPath(); ctx.moveTo(x0, pad); ctx.lineTo(x0, base); ctx.moveTo(x1, pad); ctx.lineTo(x1, base); ctx.stroke();
    }
    if (win && st.playhead != null) { const x = timeToX(inst, win.end); ctx.strokeStyle = '#ff2bd6'; ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(x, pad - 2); ctx.lineTo(x, base + 2); ctx.stroke(); ctx.lineWidth = 1; }
    if (inst.drag) { const x0 = Math.min(inst.drag.x0, inst.drag.x1), x1 = Math.max(inst.drag.x0, inst.drag.x1); ctx.fillStyle = 'rgba(154,252,255,.14)'; ctx.fillRect(x0, pad, x1 - x0, base - pad); }
    ctx.fillStyle = 'rgba(138,169,187,.9)'; ctx.font = '11px ui-monospace, monospace';
    ctx.textAlign = 'left'; ctx.fillText(UTC.full(b.min), pad, h - 3);
    ctx.textAlign = 'right'; ctx.fillText(UTC.full(b.max), w - pad, h - 3); ctx.textAlign = 'left';
    syncControls(inst, win);
  }
  function syncControls(inst, win) {
    const h = inst.host, st = Investigation.st;
    h.querySelectorAll('[data-tl-axis]').forEach(b => { const on = b.dataset.tlAxis === st.axis; b.classList.toggle('is-active', on); b.setAttribute('aria-pressed', String(on)); });
    const unknown = Evidence.index().untimed.length;
    h.querySelector('[data-tl-unknown-count]').textContent = unknown.toLocaleString();
    h.querySelector('[data-tl-unknown]').checked = st.includeUnknown;
    h.querySelector('[data-tl-unknown-wrap]').hidden = st.axis !== 'event';
    const scrub = h.querySelector('[data-tl-scrub]');
    scrub.disabled = !win;
    if (win && document.activeElement !== scrub) scrub.value = st.playhead == null ? 1000 : Math.round((win.end - win.start) / Math.max(1, win.windowEnd - win.start) * 1000);
    if (win) scrub.setAttribute('aria-valuetext', 'Playhead ' + UTC.full(win.end));
    const play = h.querySelector('[data-tl-play]');
    play.disabled = !win; play.setAttribute('aria-pressed', String(playing()));
    play.querySelector('span').textContent = playing() ? 'PAUSE' : 'PLAY';
    play.querySelector('use').setAttribute('href', playing() ? '#i-pause' : '#i-play');
    const label = h.querySelector('[data-tl-label]');
    const vis = Investigation.visible().length;
    label.textContent = win ? (st.axis === 'event' ? 'EVENT ' : 'INGESTION ') + UTC.full(win.start) + ' → ' + UTC.full(win.end) + ' · ' + vis.toLocaleString() + ' records' + (st.playhead != null ? ' (playhead)' : '') : Evidence.count ? 'No timestamped records' : 'No evidence imported';
    const s = h.querySelector('[data-tl-start]'), e = h.querySelector('[data-tl-end]');
    if (s && win && document.activeElement !== s) s.value = UTC.input(win.start);
    if (e && win && document.activeElement !== e) e.value = UTC.input(win.windowEnd);
  }
  function playing() { return !!playTimer; }
  function play() {
    let w = Investigation.windowRange(); if (!w) return;
    if (Investigation.st.playhead == null || w.end >= w.windowEnd) { Investigation.setPlayhead(w.start); w = Investigation.windowRange(); }
    playFrom = w.end; playStarted = performance.now();
    playTimer = setInterval(() => {
      const win = Investigation.windowRange(); if (!win) { stop(); return; }
      const t = playFrom + (performance.now() - playStarted) / PLAY_MS * playSpeed * (win.windowEnd - win.start);
      if (t >= win.windowEnd) { stop(); Investigation.setPlayhead(null); return; }
      Investigation.setPlayhead(t);
    }, REDUCED ? 500 : 150);
    drawAll();
  }
  function stop() { if (playTimer) { clearInterval(playTimer); playTimer = null; drawAll(); } }
  function drawAll() { if (raf) return; raf = requestAnimationFrame(() => { raf = null; for (const inst of instances) if (inst.host.isConnected && inst.host.offsetParent !== null) draw(inst); }); }
  return { create, drawAll, stop, playing };
})();

/* ============================================================== WORKSPACE VIEW */
const Workspace = (() => {
  let mounted = false, mesh = null, dirty = new Set(), renderTimer = null, receiptSel = null, findingFilter = 'window', caseSel = null, caseDraft = null, caseDirty = false;
  let explorer = { page: 0, selected: null, scope: null, query: '', kind: '', quality: '', inWindow: true };
  let timelineMain = null, timelineMesh = null;
  const say = msg => { const el = $('#irStatus'); if (el) el.textContent = msg; };
  function schedule(...parts) {
    parts.forEach(p => dirty.add(p));
    if (renderTimer) return;
    const busy = !!Ingest.current;
    renderTimer = setTimeout(() => { renderTimer = null; const d = new Set(dirty); dirty.clear(); render(d); }, busy ? 350 : 16);
  }
  function render(parts) {
    if (parts.has('receipts')) renderReceipts();
    if (parts.has('progress')) renderProgress();
    if (parts.has('findings')) renderFindings();
    if (parts.has('detail')) renderDetail();
    if (parts.has('explorer')) renderExplorer();
    if (parts.has('cases')) renderCases();
    if (parts.has('chips')) renderChips();
    if (parts.has('timeline')) Timeline.drawAll();
    if (parts.has('mesh')) MeshBridge.schedule(Ingest.current ? 600 : 30);
    SecurityFabric.render();
  }

  /* ---------------------------------------------------------------- intake */
  function initIntake() {
    const zone = $('#irZone');
    const offsets = []; for (let m = -12 * 60; m <= 14 * 60; m += 30) offsets.push(m);
    zone.innerHTML = offsets.filter(m => m % 60 === 0 || [330, 345, 570, -210, 270, 390, 630].includes(m) || m === 345).map(m => `<option value="${m}" ${m === 0 ? 'selected' : ''}>UTC${m === 0 ? '' : (m > 0 ? '+' : '−') + String(Math.floor(Math.abs(m) / 60)).padStart(2, '0') + ':' + String(Math.abs(m) % 60).padStart(2, '0')}</option>`).join('');
    $('#irYear').value = new Date().getUTCFullYear();
    $('#irLimits').textContent = 'Limits: ' + Evidence.LIMITS.records.toLocaleString() + ' records per session (imports stop at the limit and say where); 1 MiB per line; raw text over ' + (NVCore.RAW_LIMIT / 1024) + ' KiB is kept as an excerpt with a digest of the full line; JSON array files up to 128 MiB. Evidence lives in this tab’s memory only; saved cases persist.';
    $('#irFiles').addEventListener('change', e => { const files = [...e.target.files]; e.target.value = ''; if (files.length) Ingest.enqueue(files); });
    const drop = $('#irDrop');
    drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('is-over'); });
    drop.addEventListener('dragleave', () => drop.classList.remove('is-over'));
    drop.addEventListener('drop', e => { e.preventDefault(); drop.classList.remove('is-over'); const files = [...(e.dataTransfer?.files || [])]; if (files.length) Ingest.enqueue(files); });
    $('#irCancel').addEventListener('click', () => Ingest.cancel());
    $('#view-investigate').addEventListener('click', e => {
      const fx = e.target.closest('[data-ir-fixture]');
      if (fx) loadFixture(fx.dataset.irFixture);
    });
  }
  function loadFixture(name) {
    if (name === 'large') {
      say('Generating 50,000 synthetic Suricata EVE events in this tab…');
      setTimeout(() => {
        const t0 = performance.now();
        const text = NVSynthetic.large(50000);
        const file = new File([text], 'large-50000.eve.json', { type: 'application/json' });
        say('Generated ' + (file.size / 1048576).toFixed(1) + ' MiB in ' + Math.round(performance.now() - t0) + ' ms. Importing…');
        Ingest.enqueue([file], { format: 'auto', label: 'synthetic/large-50000.eve.json' });
      }, 30);
      return;
    }
    const set = (typeof NV_FIXTURES !== 'undefined' ? NV_FIXTURES : {})[name] || [];
    if (!set.length) { say('Fixture set ' + name + ' is not embedded in this build.'); return; }
    for (const f of set) Ingest.enqueue([new File([f.text], f.name.split('/').pop())], { format: 'auto', label: 'synthetic/' + f.name });
  }
  function renderProgress() {
    const cur = Ingest.current, box = $('#irProgress');
    if (!box) return;
    box.hidden = !cur;
    if (!cur) return;
    const p = cur.progress, total = cur.entry.fileSize || 1;
    const pct = p ? Math.min(100, Math.round(p.bytes / total * 100)) : 0;
    $('#irProgressBar').value = pct; $('#irProgressPct').textContent = pct + '%';
    $('#irProgressLabel').textContent = (cur.cancelRequestedAt ? 'CANCELLING · ' : 'READING · ') + cur.entry.fileName + (p ? ' · ' + p.lines.toLocaleString() + ' lines · ' + p.accepted.toLocaleString() + ' accepted · ' + p.rejected.toLocaleString() + ' rejected · ' + p.duplicates.toLocaleString() + ' duplicate' : '') + (Ingest.queued ? ' · ' + Ingest.queued + ' queued' : '');
    $('#irCancel').disabled = !!cur.cancelRequestedAt;
  }

  /* ---------------------------------------------------------------- receipts */
  const STATUS = { running: ['IMPORTING', ''], complete: ['COMPLETE', 'ok'], limit: ['PARTIAL / LIMIT', 'warn'], cancelled: ['CANCELLED / ROLLED BACK', 'warn'], failed: ['FAILED', 'alert'], unrecognized: ['NOT RECOGNISED', 'alert'], removed: ['REMOVED BY OPERATOR', ''], cleared: ['CLEARED', ''] };
  function renderReceipts() {
    const list = [...Ingest.imports.values()].reverse();
    $('#irReceiptCount').textContent = list.length + ' IMPORT' + (list.length === 1 ? '' : 'S');
    $('#irReceiptList').innerHTML = list.map(e => {
      const r = e.receipt, [label, tone] = STATUS[e.status] || [e.status.toUpperCase(), ''];
      return `<button class="ir-receipt ${receiptSel === e.importId ? 'is-selected' : ''}" role="listitem" data-ir-receipt="${esc(e.importId)}"><span>${irPill(label, tone)} ${e.synthetic ? irPill('SYNTHETIC', 'info') : ''}</span><strong>${esc(e.fileName)}</strong><small>${r ? esc((r.formatLabel || r.format || 'unknown format') + ' · ' + (r.accepted ?? 0).toLocaleString() + ' accepted · ' + (r.rejected ?? '—').toLocaleString() + ' rejected · ' + ((r.duplicates?.withinFile ?? 0) + (r.duplicates?.acrossImports ?? 0)).toLocaleString() + ' duplicate') : 'in progress'}</small></button>`;
    }).join('') || '<p class="fabric-empty">No imports yet.</p>';
    const sel = Ingest.imports.get(receiptSel) || list[0];
    if (sel) receiptSel = sel.importId;
    $('#irReceiptDetail').innerHTML = sel ? receiptHTML(sel) : '<p class="fabric-empty">Each import produces a receipt: accepted, rejected and duplicate records, timestamp assumptions, conflicts and any limit that stopped it.</p>';
  }
  function receiptHTML(e) {
    const r = e.receipt;
    if (!r) return `<p class="fabric-muted">Importing ${esc(e.fileName)}…</p>`;
    const tq = Object.entries(r.timeQuality || {}).sort((a, b) => b[1] - a[1]);
    const totalTq = tq.reduce((n, [, v]) => n + v, 0) || 1;
    const row = (k, v, tone = '') => `<div><dt>${esc(k)}</dt><dd data-tone="${tone}">${esc(v)}</dd></div>`;
    const dups = r.duplicates || {};
    return `<div class="ir-receipt-head"><h3>${esc(e.fileName)}</h3>${irPill((STATUS[e.status] || [e.status])[0], (STATUS[e.status] || [])[1])}</div>
      ${r.error ? `<p class="ir-alert">${esc(r.error)}</p>` : ''}
      ${r.limit ? `<p class="ir-alert">STOPPED AT LINE ${esc(r.limit.atLine)}: ${esc(r.limit.reason)} Records before that line were kept; everything after it was not imported.</p>` : ''}
      ${r.cancelled ? `<p class="ir-alert">Cancelled at line ${esc(r.cancelled.atLine)} after ${(r.cancelled.bytesRead / 1048576).toFixed(1)} MiB. The ${esc((r.rolledBack ?? 0).toLocaleString())} records already imported were removed so no partial file remains.</p>` : ''}
      ${e.status === 'removed' ? `<p class="ir-alert">Removed by operator at ${esc(e.removedAt)}: ${esc(e.removedRecords)} records left the workspace. This receipt is kept for the record.</p>` : ''}
      <dl class="ir-dl">
        ${row('Format', (r.formatLabel || r.format || 'not recognised') + (r.detection ? ' — ' + r.detection.method + ': ' + r.detection.reason : ''))}
        ${row('File SHA-256', e.fileSha256 || (e.hashError ? 'not computed: ' + e.hashError : 'computing…'))}
        ${row('File size', e.fileSize != null ? e.fileSize.toLocaleString() + ' bytes' : '—')}
        ${row('Lines read', r.linesRead != null ? r.linesRead.toLocaleString() : 'not reported by this path')}
        ${row('Accepted', (r.accepted ?? 0).toLocaleString(), 'ok')}
        ${row('Rejected', r.rejected == null ? 'not reported by this path' : r.rejected.toLocaleString(), r.rejected ? 'alert' : '')}
        ${row('Duplicates', dups.withinFile == null ? 'not reported by this path' : (dups.withinFile + dups.acrossImports).toLocaleString() + ' (' + dups.withinFile + ' within file, ' + dups.acrossImports + ' already imported)', (dups.withinFile + dups.acrossImports) ? 'warn' : '')}
        ${row('Conflicts', r.conflicts?.timestamp == null ? 'not reported by this path' : r.conflicts.timestamp + ' timestamp, ' + r.conflicts.identity + ' identity', (r.conflicts?.timestamp || r.conflicts?.identity) ? 'warn' : '')}
        ${row('Metadata / blank lines', (r.metadataLines ?? 0) + ' / ' + (r.blankLines ?? 0))}
        ${row('Raw stored as excerpt', String(r.rawTruncated ?? 0))}
        ${row('Assumptions', 'zone UTC' + (r.options?.zoneOffsetMinutes ? (r.options.zoneOffsetMinutes > 0 ? '+' : '') + r.options.zoneOffsetMinutes / 60 : '') + ' · syslog year ' + (r.options?.syslogYear ?? '—') + ' · slash dates ' + (r.options?.slashOrder ?? '—'))}
        ${row('Duration', r.durationMs != null ? r.durationMs.toLocaleString() + ' ms' : '—')}
      </dl>
      ${r.columnMapping ? `<p class="ir-hint">Column mapping: ${esc(Object.entries(r.columnMapping).map(([k, v]) => k + ' ← ' + v).join(' · '))}</p>` : ''}
      ${tq.length ? `<h4>EVENT-TIME QUALITY</h4><div class="ir-bars">${tq.map(([q, n]) => `<div><span>${esc(QUALITY_LABEL[q] || q)}</span><i style="--w:${(n / totalTq * 100).toFixed(1)}%" data-tone="${qualityTone(q)}"></i><b>${n.toLocaleString()}</b></div>`).join('')}</div>` : ''}
      ${(r.assumptions || []).length ? `<h4>TIMESTAMP ASSUMPTIONS</h4><ul class="ir-list">${r.assumptions.map(a => `<li>${esc(a)}</li>`).join('')}</ul>` : ''}
      ${(r.notes || []).length ? `<ul class="ir-list">${r.notes.map(a => `<li>${esc(a)}</li>`).join('')}</ul>` : ''}
      ${Object.keys(r.rejectReasons || {}).length ? `<h4>REJECTED RECORDS BY REASON</h4><table class="ir-mini"><tbody>${Object.entries(r.rejectReasons).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${v.toLocaleString()}</td></tr>`).join('')}</tbody></table>
        <p class="ir-hint">Rejected line numbers: ${esc((r.rejectedLines || []).slice(0, 40).map(([a, b]) => a === b ? a : a + '–' + b).join(', '))}${(r.rejectedLines || []).length > 40 ? ' …' : ''}. First ${Math.min(200, r.rejectSamples.length)} shown with excerpts.</p>
        <div class="ir-samples">${r.rejectSamples.slice(0, 50).map(s => `<div><b>LINE ${esc(s.line)}</b> ${esc(s.reason)}<code>${esc(s.excerpt)}</code></div>`).join('')}</div>` : ''}
      ${(r.duplicateSamples || []).length ? `<h4>DUPLICATES (FIRST ${r.duplicateSamples.length})</h4><div class="ir-samples">${r.duplicateSamples.slice(0, 20).map(s => `<div><b>LINE ${esc(s.line)}</b> identical to ${esc(s.firstSeen.source)} line ${esc(s.firstSeen.line)} — kept once, location recorded on that record</div>`).join('')}</div>` : ''}
      ${(r.conflictSamples || []).length ? `<h4>CONFLICTING OBSERVATIONS</h4><div class="ir-samples">${r.conflictSamples.slice(0, 20).map(s => `<div><b>LINE ${esc(s.line)}</b> ${esc(s.key)} — ${esc(s.detail)} Both records were kept.</div>`).join('')}</div>` : ''}
      <div class="ir-actions">
        ${['complete', 'limit'].includes(e.status) ? `<button class="btn btn--sm" data-ir-records="${esc(e.importId)}">SHOW RECORDS</button><button class="btn btn--sm btn--danger" data-ir-remove="${esc(e.importId)}">REMOVE IMPORT</button>` : ''}
        ${e.status === 'unrecognized' && e.file ? `<button class="btn btn--sm" data-ir-astext="${esc(e.importId)}">IMPORT AS GENERIC TEXT (UNVERIFIED)</button>` : ''}
        <button class="btn btn--sm" data-ir-receipt-export="${esc(e.importId)}">EXPORT RECEIPT JSON</button>
      </div>`;
  }

  /* ---------------------------------------------------------------- findings */
  const SEV_TONE = { high: 'alert', medium: 'warn', low: 'info', info: '' };
  const CONF_TONE = { high: 'alert', moderate: 'warn', low: 'info', 'not assessed': '' };
  function renderFindings() {
    const st = Investigation.st;
    const list = st.findings.filter(f => findingFilter === 'all' || Investigation.findingInWindow(f));
    $('#irFindingCount').textContent = list.length + ' / ' + st.findings.length;
    $$('[data-ir-ffilter]').forEach(b => { const on = b.dataset.irFfilter === findingFilter; b.classList.toggle('is-active', on); b.setAttribute('aria-pressed', String(on)); });
    $('#irFindingList').innerHTML = list.map(f => `<button class="ir-finding ${f.id === st.finding ? 'is-selected' : ''}" data-ir-finding="${esc(f.id)}" aria-pressed="${f.id === st.finding}">
        <span class="ir-finding__rule">${esc(f.ruleId)} v${esc(f.ruleVersion)}</span>
        <strong>${esc(f.title)}</strong>
        <span class="ir-finding__pills">${irPill('SEVERITY ' + f.severity.toUpperCase(), SEV_TONE[f.severity])}${irPill('EVIDENCE ' + f.completeness.toUpperCase(), f.completeness === 'complete' ? 'ok' : 'warn')}${irPill('CONFIDENCE ' + f.confidence.toUpperCase(), CONF_TONE[f.confidence])}</span>
        <small>${f.window ? esc(UTC.full(f.window.start) + ' · ' + UTC.span(f.window.end - f.window.start)) : 'no usable time'} · ${f.evidenceTotal.toLocaleString()} record(s)</small>
      </button>`).join('') || `<p class="fabric-empty">${st.rulesPending || Ingest.current ? 'Rules run after each import completes…' : Evidence.count ? 'No rule matched ' + (findingFilter === 'window' ? 'within this window' : 'the imported evidence') + '. That does not establish the activity was benign; check rule coverage for what could not be evaluated.' : 'Import evidence to evaluate the rules.'}</p>`;
    $('#irCoverageBody').innerHTML = (st.ruleset ? `<p class="ir-hint">${esc(st.ruleset)} · ${st.rulesRecords.toLocaleString()} records evaluated in ${st.rulesMs} ms${st.rulesAt ? ' · ' + esc(UTC.clock(st.rulesAt)) + ' UTC' : ''}. Rules run over all session evidence; the window only filters what is shown.</p>` : '') +
      st.coverage.map(c => `<div class="ir-cov"><div>${irPill(c.status.toUpperCase(), c.status === 'evaluated' ? 'ok' : c.status === 'insufficient' ? 'alert' : '')} <b>${esc(c.ruleId)} v${esc(c.version)}</b> ${esc(c.title)}</div><p>${esc(c.detail)}</p><small>${c.evaluated.toLocaleString()} evaluated · ${c.findings} finding(s)${Object.keys(c.excluded).length ? ' · excluded: ' + esc(Object.entries(c.excluded).map(([k, v]) => v.toLocaleString() + ' ' + k).join(', ')) : ''}</small></div>`).join('');
  }

  /* ---------------------------------------------------------------- detail panes */
  function recordList(ids, limit = 25) {
    const recs = ids.map(id => Evidence.get(id)).filter(Boolean);
    const missing = ids.length - recs.length;
    return `<table class="ir-mini ir-evidence"><thead><tr><th scope="col">Event time</th><th scope="col">Source:line</th><th scope="col">Record</th></tr></thead><tbody>${recs.slice(0, limit).map(r => `<tr data-ir-record="${esc(r.id)}" tabindex="0"><td>${esc(UTC.full(r.time))}<br>${irPill(QUALITY_LABEL[r.timeQuality] || r.timeQuality, qualityTone(r.timeQuality))}</td><td>${esc(r.source)}:${esc(r.line ?? '—')}</td><td>${esc(r.message.slice(0, 160))}</td></tr>`).join('')}</tbody></table>
      <p class="ir-hint">${recs.length > limit ? 'Showing ' + limit + ' of ' + recs.length.toLocaleString() + '. ' : ''}${missing ? missing + ' supporting record(s) are no longer in this session (import removed). ' : ''}</p>`;
  }
  function findingHTML(f, { compact = false } = {}) {
    const list = items => `<ul class="ir-list">${items.map(x => `<li>${esc(x)}</li>`).join('')}</ul>`;
    return `<div class="ir-detail__head"><span class="ir-finding__rule">${esc(f.ruleId)} v${esc(f.ruleVersion)} · ${esc(f.ruleset)} · ${esc(f.id)}</span><h3>${esc(f.title)}</h3></div>
      <div class="ir-triad">
        <div><span>SEVERITY</span><b data-tone="${SEV_TONE[f.severity]}">${esc(f.severity.toUpperCase())}</b><p>${esc(f.severityBasis)}</p></div>
        <div><span>EVIDENCE COMPLETENESS</span><b data-tone="${f.completeness === 'complete' ? 'ok' : 'warn'}">${esc(f.completeness.toUpperCase())}</b><p>${esc(f.completenessNotes.join(' ') || 'Every supporting record has the fields and timestamp precision the rule uses.')}</p></div>
        <div><span>CONFIDENCE (IN THE INTERPRETATION)</span><b data-tone="${CONF_TONE[f.confidence]}">${esc(f.confidence.toUpperCase())}</b><p>${esc(f.confidenceBasis.join(' '))}</p></div>
      </div>
      <h4>WHAT THE RECORDS SHOW</h4><p>${esc(f.summary)}</p>
      <h4>INTERPRETATION UNDER REVIEW</h4><p>${esc(f.interpretation)}</p>
      ${f.corroboration?.length ? `<h4>CORROBORATION</h4>${list(f.corroboration)}` : ''}
      <h4>WINDOW</h4><p>${f.window ? esc(UTC.precise(f.window.start) + ' → ' + UTC.precise(f.window.end) + ' (' + UTC.span(f.window.end - f.window.start) + ')') : 'No usable timestamps.'}</p>
      <h4>THRESHOLDS</h4><table class="ir-mini"><thead><tr><th scope="col">Test</th><th scope="col">Rule</th><th scope="col">Observed</th></tr></thead><tbody>${f.thresholds.map(t => `<tr><td>${esc(t.name)}</td><td>${esc(t.threshold)}</td><td>${esc(t.observed)}${t.met === true ? ' ✓' : ''}</td></tr>`).join('')}</tbody></table>
      <h4>ASSETS INVOLVED</h4><div class="ir-assets">${f.assets.map(a => `<button class="ir-asset" data-ir-asset="${esc(a.key)}"><b>${esc(a.key.replace(/^(dns|user|host):/, ''))}</b><small>${esc(KIND_LABEL[a.kind === 'ip' ? (NVCore.isInternal(a.key) ? 'internal' : 'external') : a.kind] || a.kind)} · ${esc(a.role)}</small></button>`).join('') || '<p class="ir-hint">No asset identifiers in the supporting records.</p>'}</div>
      ${compact ? '' : `<h4>SUPPORTING RECORDS (${f.evidenceTotal.toLocaleString()})</h4>${recordList(f.evidenceIds)}<button class="btn btn--sm" data-ir-scope-finding="${esc(f.id)}">OPEN ALL IN EVENT EXPLORER</button>`}
      <h4>ALTERNATIVE EXPLANATIONS</h4>${list(f.alternatives)}
      <h4>WHAT REMAINS UNKNOWN</h4>${list(f.missingContext)}
      <h4>INVESTIGATE NEXT</h4>${list(f.nextSteps)}
      ${f.related?.length ? `<h4>RELATED FINDINGS</h4><div class="ir-actions">${f.related.map(id => { const g = Investigation.st.findings.find(x => x.id === id); return g ? `<button class="btn btn--sm" data-ir-finding="${esc(id)}">${esc(g.ruleId)} · ${esc(g.title.slice(0, 60))}</button>` : ''; }).join('')}</div>` : ''}
      <div class="ir-actions ir-actions--sticky">
        <button class="btn btn--sm" data-ir-focus-mesh="finding">INSPECT IN FULL MESH</button>
        <button class="btn btn--sm" data-ir-window-finding="${esc(f.id)}">SET TIMELINE TO FINDING</button>
        <button class="btn btn--sm btn--primary" data-ir-case-from="${esc(f.id)}">CREATE CASE</button>
        ${caseSel ? `<button class="btn btn--sm" data-ir-case-add-finding="${esc(f.id)}">ADD TO OPEN CASE</button>` : ''}
      </div>`;
  }
  function recordsForAsset(k, list) {
    return list.filter(r => r.src === k || r.dst === k || (r.answers && r.answers.includes(k)) || ('dns:' + r.query) === k || (r.user && accountKeyOf(r) === k) || ('host:' + r.host) === k);
  }
  function assetHTML(k, { compact = false } = {}) {
    const g = Investigation.graph(), n = g.nodes.get(k);
    const label = k.replace(/^(dns|user|host):/, '');
    const kind = n?.kind || (k.startsWith('dns:') ? 'domain' : k.startsWith('user:') ? 'account' : k.startsWith('host:') ? 'host' : NVCore.isInternal(k) ? 'internal' : 'external');
    const scope = kind === 'internal' || kind === 'external' ? NVCore.ipScope(k) : null;
    const findings = Investigation.st.findings.filter(f => f.assets.some(a => a.key === k));
    const edges = [...g.edges.values()].filter(e => e.a === k || e.b === k).sort((a, b) => b.count - a.count);
    const recs = n ? n.ids : [];
    const all = recordsForAsset(k, Evidence.all());
    const w = Investigation.windowRange();
    let spark = '';
    if (n && w && all.length) {
      const bins = new Array(24).fill(0), span = Math.max(1, (w.bounds.max - w.bounds.min));
      for (const r of all) if (r.time != null) bins[Math.min(23, Math.floor((r.time - w.bounds.min) / span * 24))]++;
      const max = Math.max(1, ...bins);
      spark = `<div class="ir-spark" role="img" aria-label="Activity of ${esc(label)} across the full evidence range">${bins.map(b => `<i style="height:${Math.max(4, b / max * 100)}%"></i>`).join('')}</div>`;
    }
    return `<div class="ir-detail__head"><span class="ir-finding__rule">${esc(KIND_LABEL[kind] || kind)}${scope ? ' · ' + esc(scope.toUpperCase()) : ''}</span><h3>${esc(label)}</h3></div>
      ${scope === 'documentation' ? '<p class="ir-hint">RFC 5737/3849 documentation range: treated as an external peer; typical of synthetic test data.</p>' : ''}
      ${n ? `<dl class="ir-dl"><div><dt>Records in window</dt><dd>${n.count.toLocaleString()}</dd></div><div><dt>First / last in window</dt><dd>${esc(UTC.full(n.first))} → ${esc(UTC.full(n.last))}</dd></div><div><dt>Records in session</dt><dd>${all.length.toLocaleString()}</dd></div></dl>${spark}` : `<p class="ir-alert">Not present in the current window. ${all.length.toLocaleString()} record(s) in the session mention it.</p>`}
      <h4>RELATIONSHIPS IN WINDOW (${edges.length})</h4>
      <div class="ir-rels">${edges.slice(0, compact ? 8 : 30).map(e => `<button class="ir-rel" data-ir-edge="${esc(e.key)}" data-kind="${esc(e.kind)}"><b>${esc(EDGE_LABEL[e.kind])}</b><span>${esc((e.a === k ? '→ ' + (g.nodes.get(e.b)?.label || e.b) : '← ' + (g.nodes.get(e.a)?.label || e.a)))}</span><small>${esc(edgeBasis(e, g))}</small></button>`).join('') || '<p class="ir-hint">No relationships in the current window.</p>'}</div>
      <h4>FINDINGS (${findings.length})</h4><div class="ir-actions">${findings.map(f => `<button class="btn btn--sm" data-ir-finding="${esc(f.id)}">${esc(f.ruleId)} · ${esc(f.severity.toUpperCase())}</button>`).join('') || '<span class="ir-hint">None of the rules cite this asset.</span>'}</div>
      ${compact ? '' : `<h4>RECORDS</h4>${recordList(recs, 15)}`}
      <div class="ir-actions"><button class="btn btn--sm" data-ir-scope-asset="${esc(k)}">SHOW RECORDS IN EXPLORER</button>${caseSel ? `<button class="btn btn--sm" data-ir-case-add-asset="${esc(k)}">ADD WINDOW RECORDS TO OPEN CASE</button>` : ''}${compact ? '<button class="btn btn--sm" data-route="investigate">OPEN IN RECONSTRUCTION ↗</button>' : ''}</div>`;
  }
  function edgeHTML(k, { compact = false } = {}) {
    const g = Investigation.graph(), e = g.edges.get(k);
    if (!e) return '<p class="fabric-empty">This relationship is not in the current window.</p>';
    const name = x => g.nodes.get(x)?.label || x;
    return `<div class="ir-detail__head"><span class="ir-finding__rule">${esc(EDGE_LABEL[e.kind])}</span><h3>${esc(name(e.a))} → ${esc(name(e.b))}</h3></div>
      <p class="${e.kind === 'inferred' ? 'ir-alert' : ''}">${esc(edgeBasis(e, g))}</p>
      ${e.kind === 'inferred' ? '<p class="ir-hint">Drawn dashed in the mesh. No single record shows this link; it follows from the timing and address match described by the finding.</p>' : '<p class="ir-hint">Drawn solid: at least one imported record states this relationship directly.</p>'}
      <dl class="ir-dl"><div><dt>Records</dt><dd>${e.count.toLocaleString()}</dd></div><div><dt>First / last</dt><dd>${esc(UTC.full(e.first))} → ${esc(UTC.full(e.last))}</dd></div></dl>
      ${compact ? '' : recordList(e.ids, 15)}
      <div class="ir-actions"><button class="btn btn--sm" data-ir-scope-edge="${esc(k)}">SHOW RECORDS IN EXPLORER</button><button class="btn btn--sm" data-ir-asset="${esc(e.a)}">${esc(name(e.a).slice(0, 40))}</button><button class="btn btn--sm" data-ir-asset="${esc(e.b)}">${esc(name(e.b).slice(0, 40))}</button></div>`;
  }
  function renderDetail() {
    const st = Investigation.st, body = $('#irDetailBody'); if (!body) return;
    const f = Investigation.finding();
    let kicker = 'SELECTION', title = 'DETAIL', html;
    if (st.edge) { kicker = 'RELATIONSHIP'; title = 'EDGE BASIS'; html = edgeHTML(st.edge); }
    else if (st.asset) { kicker = 'ASSET'; title = 'ASSET DOSSIER'; html = assetHTML(st.asset); }
    else if (f) { kicker = 'FINDING'; title = 'FINDING DOSSIER'; html = findingHTML(f); }
    else html = `<p class="fabric-empty">Select a finding to see the rule, its exact supporting records, thresholds, alternatives and what remains unknown. Select a node or a line in the mesh to see what evidence created it.</p>
      <h4>MESH LEGEND</h4>${legendHTML()}`;
    $('#irDetailKicker').textContent = kicker; $('#irDetailTitle').textContent = title;
    body.innerHTML = html;
  }
  function legendHTML() {
    return `<ul class="ir-legend-list">
      <li><i data-k="internal"></i>Internal address (RFC 1918/ULA) — inner sphere</li>
      <li><i data-k="external"></i>External address — equatorial ring</li>
      <li><i data-k="domain"></i>DNS name — outer ring</li>
      <li><i data-k="account"></i>Account · <i data-k="host"></i>Logging host — lower cap</li>
      <li><i data-e="comm"></i>Observed communication (solid, particles show recorded direction)</li>
      <li><i data-e="dns"></i>Observed DNS lookup / answer</li>
      <li><i data-e="auth"></i>Observed authentication</li>
      <li><i data-e="inferred"></i>Inferred association (dashed) — from a finding, not a single record</li>
      <li><i data-k="sim"></i>Dim slate lattice: training simulation, not evidence</li></ul>`;
  }
  function renderChips() {
    const s = MeshBridge.stats;
    const chip = $('#irMeshChip'); if (chip) chip.textContent = s.shown + (s.total > s.shown ? ' OF ' + s.total.toLocaleString() : '') + ' ASSETS';
    const legend = $('#irLegend');
    if (legend) legend.textContent = s.total > s.shown ? 'Showing ' + s.shown + ' of ' + s.total.toLocaleString() + ' assets in the window (finding assets and the selection first, then most records) and ' + s.edgesShown + ' of ' + s.edgesTotal.toLocaleString() + ' relationships. The explorer and asset dossiers include everything.' : s.total ? s.total + ' assets and ' + s.edgesTotal + ' relationships in the window.' : 'No evidence assets in the window. Dim slate nodes are the training lattice.';
    const eng = $('#irEngineChip'); if (eng) { eng.textContent = Ingest.mode === 'worker' ? 'WORKER ENGINE' : Ingest.mode === 'main-thread' ? 'MAIN-THREAD FALLBACK' : 'ENGINE STARTING'; eng.title = Ingest.note || 'Parsing and rules run in a background worker.'; }
    const w = Investigation.windowRange();
    const wc = $('#irWindowChip'); if (wc) wc.textContent = w ? Investigation.visible().length.toLocaleString() + ' IN WINDOW' : Evidence.count ? 'NO TIMES' : 'NO EVIDENCE';
    const steps = { import: Ingest.imports.size > 0, quality: [...Ingest.imports.values()].some(e => e.receipt), findings: Investigation.st.findings.length > 0, mesh: !!(Investigation.st.finding || Investigation.st.asset), timeline: !!(Investigation.st.window || Investigation.st.playhead != null), case: CaseStore.list().length > 0 };
    $$('[data-ir-step]').forEach(a => a.classList.toggle('is-done', !!steps[a.dataset.irStep]));
  }

  /* ---------------------------------------------------------------- explorer */
  function explorerRows() {
    let base;
    if (explorer.scope) base = [...explorer.scope.ids].map(id => Evidence.get(id)).filter(Boolean).sort((a, b) => (a.time ?? Infinity) - (b.time ?? Infinity));
    else if (explorer.inWindow) base = Investigation.visible();
    else { const ix = Evidence.index(); base = ix.timed.concat(ix.untimed); }
    const tokens = explorer.query.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
    const parsed = tokens.map(t => { const neg = t.startsWith('-') && t.length > 1; if (neg) t = t.slice(1); const m = t.match(/^(src|dst|port|host|user|query|kind|format|quality|source|line|severity|origin|id)[:=](.*)$/i); return { neg, field: m ? m[1].toLowerCase() : null, needle: (m ? m[2] : t).replace(/"/g, '').toLowerCase() }; }).filter(t => t.needle);
    const q = explorer.quality, k = explorer.kind;
    return base.filter(r => {
      if (k && r.kind !== k) return false;
      if (q === 'exact' && !EXACT_Q.has(r.timeQuality)) return false;
      if (q === 'assumed' && !['assumed-zone', 'assumed-year', 'date-only', 'adapter', 'migrated'].includes(r.timeQuality)) return false;
      if (q === 'unknown' && r.time != null) return false;
      if (q === 'conflict' && !r.conflicts?.length) return false;
      for (const t of parsed) {
        const field = t.field === 'quality' ? 'timeQuality' : t.field;
        const hay = field ? String(r[field] ?? '').toLowerCase() : (r.message + ' ' + (r.raw || '') + ' ' + r.source).toLowerCase();
        const hit = hay.includes(t.needle);
        if (t.neg ? hit : !hit) return false;
      }
      return true;
    });
  }
  let explorerCache = null;
  function renderExplorer() {
    const rows = explorerRows();
    explorerCache = rows;
    const pages = Math.max(1, Math.ceil(rows.length / 100));
    explorer.page = Math.min(explorer.page, pages - 1);
    $('#irExplorerCount').textContent = rows.length.toLocaleString() + ' / ' + Evidence.count.toLocaleString();
    const scope = $('#irScope');
    scope.hidden = !explorer.scope;
    if (explorer.scope) scope.innerHTML = `${irPill('SCOPE', 'info')} ${esc(explorer.scope.label)} <button class="btn btn--sm" data-ir-scope-clear>CLEAR SCOPE</button>`;
    $('#irRows').innerHTML = rows.slice(explorer.page * 100, explorer.page * 100 + 100).map(r => `<tr data-ir-record="${esc(r.id)}" tabindex="0" class="${r.id === explorer.selected ? 'is-selected' : ''}">
        <td>${esc(UTC.full(r.time))}<br>${irPill(QUALITY_LABEL[r.timeQuality] || r.timeQuality, qualityTone(r.timeQuality))}${r.conflicts?.length ? irPill('CONFLICT', 'alert') : ''}${r.alsoSeenCount ? irPill('×' + (r.alsoSeenCount + 1) + ' SEEN', 'warn') : ''}</td>
        <td>${esc(r.source)}:${esc(r.line ?? '—')}<br>${irPill(r.kind.toUpperCase())} ${r.origin !== 'IMPORT' ? irPill(r.origin, 'info') : ''}${r.severity !== 'info' ? irPill('SOURCE ' + r.severity.toUpperCase(), SEV_TONE[r.severity]) : ''}</td>
        <td>${esc(r.message.slice(0, 260))}</td></tr>`).join('') || `<tr><td colspan="3">${Evidence.count ? 'No records match these filters' + (explorer.inWindow && !explorer.scope ? ' in the current window' : '') + '.' : 'Import evidence to populate the explorer.'}</td></tr>`;
    $('#irPage').textContent = 'PAGE ' + (explorer.page + 1) + ' / ' + pages;
    $('#irPrev').disabled = explorer.page === 0; $('#irNext').disabled = explorer.page >= pages - 1;
    renderRecord();
  }
  function renderRecord() {
    const r = explorer.selected && Evidence.get(explorer.selected);
    const host = $('#irRecord');
    if (!r) { host.innerHTML = '<p class="fabric-empty">Select a record to see its original text, source file and line, both timestamps, and any conflicts.</p>'; return; }
    const entry = Ingest.imports.get(r.importId);
    const fields = ['kind', 'src', 'srcPort', 'dst', 'port', 'proto', 'host', 'user', 'outcome', 'authMethod', 'query', 'qtype', 'rcode', 'answers', 'signature', 'severity', 'uid', 'repeat'].filter(k => r[k] != null && r[k] !== '' && !(k === 'repeat' && r[k] === 1));
    host.innerHTML = `<div class="ir-record__head"><h3>${esc(r.source)} · line ${esc(r.line ?? '—')}</h3><span>${esc(r.id)}</span></div>
      <dl class="ir-dl">
        <div><dt>Event time</dt><dd>${esc(UTC.precise(r.time))} ${irPill(QUALITY_LABEL[r.timeQuality] || r.timeQuality, qualityTone(r.timeQuality))}</dd></div>
        <div><dt>Source timestamp text</dt><dd>${esc(r.timeText ?? '—')}</dd></div>
        ${r.timeNote ? `<div><dt>Time note</dt><dd>${esc(r.timeNote)}</dd></div>` : ''}
        <div><dt>Ingestion time</dt><dd>${esc(UTC.precise(r.received))}</dd></div>
        <div><dt>Format / origin</dt><dd>${esc(NVCore.FORMATS[r.format] || r.format)} · ${esc(r.origin)}</dd></div>
        <div><dt>Import</dt><dd>${esc(r.importId)}${entry?.fileSha256 ? ' · file SHA-256 ' + esc(entry.fileSha256) : ''}</dd></div>
        <div><dt>Raw line SHA-256</dt><dd>${esc(r.rawSha256 || '—')} (${esc((r.rawBytes ?? 0).toLocaleString())} bytes)</dd></div>
        ${fields.map(k => `<div><dt>${esc(k)}</dt><dd>${esc(Array.isArray(r[k]) ? r[k].join(', ') : r[k])}</dd></div>`).join('')}
        ${r.alsoSeenAt?.length ? `<div><dt>Identical copies</dt><dd>${esc(r.alsoSeenAt.map(l => l.source + ':' + l.line).join(', '))}${r.alsoSeenCount > r.alsoSeenAt.length ? ' …' : ''}</dd></div>` : ''}
      </dl>
      ${r.conflicts?.length ? `<h4>CONFLICTS</h4><ul class="ir-list">${r.conflicts.map(c => `<li>${esc(c.detail)}${c.otherId ? ' Other record: ' + esc(c.otherId) + '.' : ''}${c.value ? ' Value: ' + esc(c.value) : ''}</li>`).join('')}</ul>` : ''}
      ${r.notes?.length ? `<h4>PARSER NOTES</h4><ul class="ir-list">${r.notes.map(n => `<li>${esc(n)}</li>`).join('')}</ul>` : ''}
      <h4>ORIGINAL RECORD${r.rawTruncated ? ' (EXCERPT — FIRST ' + NVCore.RAW_LIMIT.toLocaleString() + ' CHARACTERS; DIGEST COVERS THE FULL LINE)' : ''}</h4>
      <pre class="ir-raw" data-ir-raw></pre>
      <div class="ir-actions">${caseSel ? '<button class="btn btn--sm" data-ir-case-add-record="' + esc(r.id) + '">ADD TO OPEN CASE</button>' : ''}${[r.src, r.dst].filter(Boolean).map(ip => `<button class="btn btn--sm" data-ir-asset="${esc(ip)}">ASSET ${esc(ip)}</button>`).join('')}</div>`;
    host.querySelector('[data-ir-raw]').textContent = r.raw ?? '(raw text not retained)';
  }
  function setScope(label, ids) { explorer.scope = { label, ids: new Set(ids) }; explorer.page = 0; renderExplorer(); $('#irExplorer').scrollIntoView({ block: 'start', behavior: REDUCED ? 'auto' : 'smooth' }); }

  /* ---------------------------------------------------------------- cases */
  function caseById(id) { return id && caseDraft?.id === id ? caseDraft : CaseStore.get(id); }
  function openCase(id) { caseSel = id; caseDraft = JSON.parse(JSON.stringify(CaseStore.get(id))); caseDirty = false; renderCases(); renderDetail(); }
  function renderCases() {
    const status = $('#irStoreStatus'), chip = $('#irStoreChip');
    chip.textContent = { indexeddb: 'INDEXEDDB / SCHEMA ' + NVCases.SCHEMA, localstorage: 'LOCALSTORAGE / SCHEMA ' + NVCases.SCHEMA, memory: 'MEMORY ONLY', none: 'STORAGE —' }[CaseStore.backend];
    chip.className = 'hud-chip ' + (CaseStore.backend === 'indexeddb' ? 'hud-chip--toxic' : CaseStore.backend === 'memory' ? 'hud-chip--mag' : 'hud-chip--amber');
    status.textContent = CaseStore.error || CaseStore.note || (CaseStore.backend === 'indexeddb' ? 'Cases are stored unencrypted in this browser profile (IndexedDB). Imported evidence is not stored unless attached to a case.' : '');
    status.dataset.tone = CaseStore.error ? 'alert' : '';
    const list = CaseStore.list();
    $('#irCaseList').innerHTML = list.map(c => `<button class="ir-case ${c.id === caseSel ? 'is-selected' : ''}" data-ir-case="${esc(c.id)}"><span>${irPill(c.status.toUpperCase())} ${irPill(c.disposition.toUpperCase().replace(/-/g, ' '), c.disposition === 'true-positive' ? 'alert' : c.disposition === 'undetermined' ? '' : 'ok')}${c.importVerification ? irPill(c.importVerification.ok ? 'IMPORTED / VERIFIED' : 'IMPORTED / FAILED CHECK', c.importVerification.ok ? 'ok' : 'alert') : ''}</span><strong>${esc(c.title)}</strong><small>${c.evidence.length.toLocaleString()} records · ${c.notes.length} notes · updated ${esc(UTC.full(Date.parse(c.updatedAt)))}</small></button>`).join('') || '<p class="fabric-empty">No saved cases.</p>';
    const c = caseSel && caseDraft;
    const ed = $('#irCaseEditor');
    if (!c) { ed.innerHTML = '<p class="fabric-empty">Create a case from a finding, or open a saved one. Cases keep their evidence, notes, disposition and history in this browser until you delete them.</p>'; return; }
    const loaded = c.evidence.filter(e => Evidence.has(e.id)).length;
    const v = c.importVerification;
    ed.innerHTML = `<div class="ir-case-editor__head"><input id="irCaseTitle" maxlength="200" aria-label="Case title" value="${esc(c.title)}"><span class="ir-save" id="irCaseSave" role="status" data-tone="${caseDirty ? 'warn' : 'ok'}">${caseDirty ? 'UNSAVED CHANGES' : 'SAVED ' + esc(UTC.clock(Date.parse(c.updatedAt))) + ' UTC'}</span></div>
      ${v ? `<p class="${v.ok ? 'ir-hint' : 'ir-alert'}">Imported ${esc(v.at)} · content ${esc(v.content)} · ${v.matched} evidence digest(s) matched, ${v.mismatched} mismatched, ${v.unverifiable} unverifiable · file SHA-256 ${esc(v.fileSha256)}</p>` : ''}
      <div class="ir-form ir-form--case">
        <label>STATUS<select id="irCaseStatus">${NVCases.STATUSES.map(s => `<option ${s === c.status ? 'selected' : ''}>${s}</option>`).join('')}</select></label>
        <label>DISPOSITION<select id="irCaseDisposition">${NVCases.DISPOSITIONS.map(s => `<option value="${s}" ${s === c.disposition ? 'selected' : ''}>${s.replace(/-/g, ' ')}</option>`).join('')}</select></label>
        <label class="ir-form__wide">DISPOSITION RATIONALE<textarea id="irCaseRationale" rows="2" maxlength="8000">${esc(c.dispositionNote)}</textarea></label>
      </div>
      <div class="ir-actions">
        <button class="btn btn--sm btn--primary" id="irCaseSaveBtn">SAVE CASE</button>
        <button class="btn btn--sm" data-ir-case-restore>RESTORE CONTEXT${loaded < c.evidence.length ? ' (LOAD ' + (c.evidence.length - loaded) + ' RECORDS)' : ''}</button>
        <button class="btn btn--sm" data-ir-case-export>EXPORT…</button>
        <button class="btn btn--sm btn--danger" data-ir-case-delete>DELETE</button>
      </div>
      <h4>NOTES (${c.notes.length})</h4>
      <div class="ir-notes">${c.notes.map(n => `<div><time>${esc(UTC.full(Date.parse(n.at)))}</time><p></p></div>`).join('') || '<p class="ir-hint">No notes yet.</p>'}</div>
      <div class="ir-note-add"><textarea id="irCaseNote" rows="2" maxlength="8000" aria-label="New note" placeholder="Record context, decisions and follow-up"></textarea><button class="btn btn--sm" id="irCaseNoteAdd">ADD NOTE</button></div>
      <h4>FINDINGS (${c.findings.length})</h4>
      <div class="ir-case-findings">${c.findings.map(f => `<div>${irPill(f.ruleId + ' v' + f.ruleVersion)} <b>${esc(f.title)}</b><small>${esc(f.summary || '')}</small></div>`).join('') || '<p class="ir-hint">No finding attached.</p>'}</div>
      <h4>EVIDENCE (${c.evidence.length.toLocaleString()} · ${loaded.toLocaleString()} loaded in this session)</h4>
      <table class="ir-mini ir-evidence"><tbody>${c.evidence.slice(0, 25).map(e => `<tr><td>${esc(UTC.full(e.time))}</td><td>${esc(e.source)}:${esc(e.line ?? '—')}</td><td>${esc((e.message || '').slice(0, 120))}</td><td class="ir-hash">${esc((e.rawSha256 || '').slice(0, 16))}…</td></tr>`).join('')}</tbody></table>
      ${c.evidence.length > 25 ? `<p class="ir-hint">Showing 25 of ${c.evidence.length.toLocaleString()}.</p>` : ''}
      <h4>SOURCES</h4><ul class="ir-list">${c.sources.map(s => `<li>${esc(s.fileName)} · ${esc(s.format || '')} · SHA-256 ${esc(s.fileSha256 || 'not recorded')}</li>`).join('')}</ul>
      <details><summary>HISTORY (${c.history.length})</summary><ul class="ir-list">${c.history.slice().reverse().map(h => `<li>${esc(UTC.full(Date.parse(h.at)))} · ${esc(h.action)} ${esc(h.detail || '')}</li>`).join('')}</ul></details>`;
    ed.querySelectorAll('.ir-notes > div > p').forEach((p, i) => { p.textContent = c.notes[i].text; });
    const mark = () => { caseDirty = true; const s = $('#irCaseSave'); s.textContent = 'UNSAVED CHANGES'; s.dataset.tone = 'warn'; };
    $('#irCaseTitle').addEventListener('input', e => { caseDraft.title = e.target.value.slice(0, 200); mark(); });
    $('#irCaseStatus').addEventListener('change', e => { NVCases.setDisposition(caseDraft, { status: e.target.value }); mark(); });
    $('#irCaseDisposition').addEventListener('change', e => { NVCases.setDisposition(caseDraft, { disposition: e.target.value }); mark(); });
    $('#irCaseRationale').addEventListener('change', e => { NVCases.setDisposition(caseDraft, { note: e.target.value }); mark(); });
    $('#irCaseNoteAdd').addEventListener('click', () => { try { NVCases.addNote(caseDraft, $('#irCaseNote').value); caseDirty = true; renderCases(); } catch (err) { setSaveStatus(err.message, 'alert'); } });
    $('#irCaseSaveBtn').addEventListener('click', saveCase);
  }
  function setSaveStatus(msg, tone) { const s = $('#irCaseSave'); if (s) { s.textContent = msg; s.dataset.tone = tone; } }
  async function saveCase() {
    if (!caseDraft) return false;
    caseDraft.updatedAt = new Date().toISOString();
    try { await CaseStore.put(caseDraft); caseDirty = false; renderCases(); renderChips(); return true; }
    catch (e) { caseDirty = true; renderCases(); setSaveStatus('NOT SAVED — ' + e.message.replace(/^Not saved: /, '') + ' Edits remain in this tab; export the case to keep a copy.', 'alert'); return false; }
  }
  function sourcesFor(records) { return [...new Set(records.map(r => r.importId))].map(id => { const e = Ingest.imports.get(id); return e ? { importId: id, fileName: e.fileName, fileSha256: e.fileSha256, fileSize: e.fileSize, format: e.receipt?.format, startedAt: e.receipt?.startedAt, assumptions: e.receipt?.assumptions } : { importId: id, fileName: id }; }); }
  async function caseFromFinding(id) {
    const f = Investigation.st.findings.find(x => x.id === id); if (!f) return;
    const recs = f.evidenceIds.map(i => Evidence.get(i)).filter(Boolean);
    let c;
    try { c = NVCases.createCase({ finding: f, records: recs, sources: sourcesFor(recs) }); }
    catch (e) { toast({ title: 'CASE NOT CREATED', msg: e.message, tone: 'mag', icon: 'warning' }); return; }
    caseSel = c.id; caseDraft = c; caseDirty = true;
    const ok = await saveCase();
    toast({ title: ok ? 'CASE CREATED' : 'CASE NOT SAVED', msg: ok ? c.evidence.length + ' supporting records attached with their digests.' : 'Storage failed; the case is open but unsaved.', tone: ok ? 'toxic' : 'mag', icon: ok ? 'check' : 'warning' });
    $('#irCases').scrollIntoView({ block: 'start', behavior: REDUCED ? 'auto' : 'smooth' });
  }
  async function attachToCase(records, finding = null) {
    if (!caseDraft) return;
    try {
      const n = NVCases.attachEvidence(caseDraft, records, sourcesFor(records));
      if (finding && !caseDraft.findings.some(x => x.id === finding.id)) { caseDraft.findings.push(NVCases.snapshotFinding(finding)); for (const a of finding.assets) if (!caseDraft.assets.some(x => x.key === a.key)) caseDraft.assets.push({ ...a }); }
      caseDirty = true; renderCases();
      toast({ title: 'EVIDENCE ATTACHED', msg: n + ' new record(s) attached. Save the case to keep them.', tone: 'cyan', icon: 'check', duration: 2600 });
    } catch (e) { toast({ title: 'NOT ATTACHED', msg: e.message, tone: 'mag', icon: 'warning' }); }
  }
  function restoreContext(c) {
    const missing = c.evidence.filter(e => !Evidence.has(e.id));
    if (missing.length) {
      const importId = 'case-' + c.id.slice(0, 8) + '-' + Date.now().toString(36).slice(-4);
      const recs = missing.map(e => ({ ...e, alsoSeenAt: null, importId: e.importId || importId }));
      let ok = 0, bad = 0, unverifiable = 0;
      for (const e of recs) { if (!e.raw || e.rawTruncated) unverifiable++; else if (NVCore.sha256Text(e.raw) === e.rawSha256) ok++; else bad++; }
      Evidence.add(recs);
      const entry = { importId, fileName: 'case: ' + c.title, fileSize: null, status: 'complete', fileSha256: null, startedAt: Date.now(), synthetic: false,
        receipt: { importId, fileName: 'case: ' + c.title, format: 'case-evidence', formatLabel: 'Evidence restored from a saved case', status: 'complete', accepted: recs.length, rejected: 0, duplicates: { withinFile: 0, acrossImports: 0 }, linesRead: recs.length, metadataLines: 0, blankLines: 0, conflicts: { timestamp: 0, identity: 0 }, rawTruncated: unverifiable, timeQuality: recs.reduce((m, r) => (m[r.timeQuality] = (m[r.timeQuality] || 0) + 1, m), {}), rejectReasons: {}, rejectSamples: [], rejectedLines: [], duplicateSamples: [], conflictSamples: [], assumptions: [], notes: ['Loaded from case ' + c.id + '. Raw digests re-checked: ' + ok + ' match, ' + bad + ' mismatch, ' + unverifiable + ' unverifiable (excerpt or redacted).'], detection: { method: 'case', reason: 'Case evidence snapshot.' }, startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), durationMs: 0 } };
      Ingest.imports.set(importId, entry);
      Ingest.addAdapterRows(importId, recs);
      receiptSel = importId;
      if (bad) toast({ title: 'DIGEST MISMATCH', msg: bad + ' case record(s) no longer match their ingestion digest.', tone: 'mag', icon: 'warning' });
    }
    const pad = c.window ? Math.max(60000, (c.window.end - c.window.start) * 0.2) : 0;
    if (Investigation.st.axis !== 'event') Investigation.setAxis('event');
    if (c.window) Investigation.setWindow(c.window.start - pad, c.window.end + pad); else Investigation.setWindow(null, null);
    const fid = c.findings.find(f => Investigation.st.findings.some(x => x.id === f.id))?.id;
    if (fid) Investigation.selectFinding(fid);
    else Investigation.focusKeys(new Set(c.assets.map(a => a.key)), 'case ' + c.title);
    setTimeout(() => { if (fid) Investigation.selectFinding(fid); }, 400);
    $('#irMeshPanel').scrollIntoView({ block: 'center', behavior: REDUCED ? 'auto' : 'smooth' });
    toast({ title: 'CASE CONTEXT RESTORED', msg: 'Timeline window and mesh focus set from the case' + (missing.length ? '; ' + missing.length + ' records loaded from the case snapshot.' : '.'), tone: 'cyan', icon: 'refresh', duration: 3200 });
  }

  /* ---------------------------------------------------------------- dialogs */
  function dialog(html) { const d = $('#irDialog'); d.innerHTML = html; if (!d.open) d.showModal(); return d; }
  function exportDialog(c) {
    const s = NVCases.sensitivity(c, text => Defense.sensitive(text));
    const d = dialog(`<div class="fabric-head"><div><span class="eyebrow">EXPORT CASE / REVIEW CONTENTS FIRST</span><h2 id="irDialogTitle">${esc(c.title)}</h2></div><button class="btn" data-ir-dialog-close>CLOSE</button></div>
      <p>This file is written to your device only. NEXUS does not upload it. Review what it contains before sharing it.</p>
      <dl class="ir-dl">
        <div><dt>Evidence records</dt><dd>${s.evidence.toLocaleString()} (${s.rawCount.toLocaleString()} with raw log lines, ${(s.rawBytes / 1024).toFixed(1)} KiB)</dd></div>
        <div><dt>IP addresses</dt><dd>${s.addresses} (${s.internalAddresses} internal)</dd></div>
        <div><dt>Account names</dt><dd>${s.accountCount}: ${esc(s.accounts.slice(0, 12).join(', '))}${s.accountCount > 12 ? ' …' : ''}</dd></div>
        <div><dt>Hostnames</dt><dd>${s.hostCount}: ${esc(s.hosts.slice(0, 12).join(', '))}</dd></div>
        <div><dt>Analyst notes</dt><dd>${s.notes} note(s) and the disposition rationale</dd></div>
        <div><dt>Credential-like content</dt><dd data-tone="${s.credentialHits.length ? 'alert' : 'ok'}">${s.credentialHits.length ? esc(s.credentialHits.length + ' item(s): ' + s.credentialHits.slice(0, 6).map(h => h.id + ' (' + h.categories.join(', ') + ')').join('; ')) : 'None of the configured patterns matched (patterns are not exhaustive).'}</dd></div>
      </dl>
      <fieldset class="ir-fieldset"><legend>RAW LOG LINES</legend>
        <label><input type="radio" name="irRaw" value="1" checked> Include raw lines (needed for anyone to re-verify each record against its digest)</label>
        <label><input type="radio" name="irRaw" value="0"> Omit raw lines. Digests and normalised fields remain — addresses, accounts, hostnames and message summaries are <b>not</b> removed; this is not anonymisation.</label>
      </fieldset>
      <label class="ir-check"><input type="checkbox" id="irExportAck"> I have reviewed what this file contains and may share it.</label>
      <p class="ir-hint">${esc(NVCases.NOTICE)}</p>
      <div class="ir-actions"><button class="btn btn--primary" id="irExportGo" disabled>WRITE EXPORT FILE</button></div><div id="irExportResult" role="status"></div>`);
    d.querySelector('#irExportAck').addEventListener('change', e => { d.querySelector('#irExportGo').disabled = !e.target.checked; });
    d.querySelector('#irExportGo').addEventListener('click', async () => {
      const includeRaw = d.querySelector('input[name=irRaw]:checked').value === '1';
      const out = NVCases.buildExport(c, { includeRaw, app: { version: NV_APP_VERSION, edition: Operations.companion ? 'local' : 'public' } });
      const name = 'nexus-case-' + c.title.replace(/[^\w.-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) + '-' + c.id.slice(0, 8) + '.json';
      downloadLocal(out.text, name);
      d.querySelector('#irExportResult').innerHTML = `<p class="ir-alert" data-tone="ok">Written as <b>${esc(name)}</b>.</p><dl class="ir-dl"><div><dt>File SHA-256</dt><dd class="ir-hash" data-ir-export-sha>${esc(out.fileSha256)}</dd></div><div><dt>Content SHA-256</dt><dd class="ir-hash">${esc(out.contentSha256)}</dd></div></dl><p class="ir-hint">Record the file digest somewhere separate (ticket, message to a colleague). Comparing it later is the only way to detect an edit where every embedded digest was recomputed.</p>${out.mismatchedAtExport.length ? `<p class="ir-alert">${out.mismatchedAtExport.length} record(s) already differed from their ingestion digest before export.</p>` : ''}`;
      NVCases.setDisposition(caseDraft, {});
      caseDraft.history.push({ at: new Date().toISOString(), action: 'exported', detail: (includeRaw ? 'with raw lines' : 'without raw lines') + '; file SHA-256 ' + out.fileSha256 });
      caseDirty = true; await saveCase();
    });
  }
  async function importCaseFile(file) {
    if (file.size > 64 * 1048576) { toast({ title: 'CASE FILE TOO LARGE', msg: 'Case exports above 64 MiB are not accepted.', tone: 'mag', icon: 'warning' }); return; }
    const text = await file.text();
    const v = NVCases.verifyExport(text);
    const r = v.report;
    const existing = v.case && CaseStore.get(v.case.id);
    const d = dialog(`<div class="fabric-head"><div><span class="eyebrow">CASE IMPORT / INTEGRITY CHECK</span><h2 id="irDialogTitle">${esc(v.case?.title || file.name)}</h2></div><button class="btn" data-ir-dialog-close>CLOSE</button></div>
      <div class="ir-verify" data-ok="${v.ok}">${v.ok ? 'INTEGRITY VERIFIED' : 'INTEGRITY CHECK FAILED'}</div>
      <dl class="ir-dl">
        <div><dt>File SHA-256</dt><dd class="ir-hash" data-ir-verify-sha>${esc(r.fileSha256)}</dd></div>
        <div><dt>Case content digest</dt><dd data-tone="${r.content === 'match' ? 'ok' : 'alert'}">${esc(r.content.toUpperCase())}</dd></div>
        <div><dt>Evidence digests</dt><dd>${r.evidence.matched} match · <span data-tone="${r.evidence.mismatched.length ? 'alert' : ''}">${r.evidence.mismatched.length} mismatch</span> · ${r.evidence.unverifiable.length} unverifiable</dd></div>
        <div><dt>Exported</dt><dd>${esc(v.exportedAt || 'unknown')}</dd></div>
      </dl>
      ${r.errors.length ? `<ul class="ir-list ir-list--alert">${r.errors.map(e => `<li>${esc(e)}</li>`).join('')}</ul>` : ''}
      ${r.warnings.length ? `<ul class="ir-list">${r.warnings.map(e => `<li>${esc(e)}</li>`).join('')}</ul>` : ''}
      ${r.evidence.mismatched.length ? `<p class="ir-hint">Mismatched records: ${esc(r.evidence.mismatched.slice(0, 20).join(', '))}</p>` : ''}
      <p class="ir-hint">${esc(r.notice)}</p>
      <div class="ir-actions">${v.case ? (existing ? `<button class="btn" data-ir-import-save="replace">REPLACE SAVED CASE</button><button class="btn" data-ir-import-save="copy">SAVE AS A COPY</button>` : `<button class="btn btn--primary" data-ir-import-save="new">${v.ok ? 'SAVE CASE' : 'SAVE ANYWAY (MARKED FAILED)'}</button>`) : ''}</div>`);
    d.querySelectorAll('[data-ir-import-save]').forEach(b => b.addEventListener('click', async () => {
      const c = JSON.parse(JSON.stringify(v.case));
      if (b.dataset.irImportSave === 'copy') { c.id = (crypto.randomUUID?.() || 'case-' + Date.now()); c.title = c.title + ' (imported copy)'; }
      c.importVerification = { at: new Date().toISOString(), ok: v.ok, content: r.content, matched: r.evidence.matched, mismatched: r.evidence.mismatched.length, unverifiable: r.evidence.unverifiable.length, fileSha256: r.fileSha256 };
      c.history.push({ at: new Date().toISOString(), action: 'imported', detail: (v.ok ? 'verified' : 'FAILED verification') + '; file SHA-256 ' + r.fileSha256 });
      try { await CaseStore.put(c); d.close(); openCase(c.id); toast({ title: 'CASE IMPORTED', msg: v.ok ? 'Digests verified and the case was saved.' : 'Saved with a failed-verification mark.', tone: v.ok ? 'toxic' : 'mag', icon: v.ok ? 'check' : 'warning' }); }
      catch (e) { d.querySelector('.ir-actions').insertAdjacentHTML('afterend', `<p class="ir-alert">${esc(e.message)}</p>`); }
    }));
  }

  /* ---------------------------------------------------------------- events */
  function bind() {
    const view = $('#view-investigate');
    view.addEventListener('click', async e => {
      const t = e.target.closest('button, [data-ir-record], a[data-ir-step]');
      if (!t) return;
      const d = t.dataset;
      if (d.irStep) { e.preventDefault(); const target = document.querySelector(t.getAttribute('href')); target?.scrollIntoView({ block: 'start', behavior: REDUCED ? 'auto' : 'smooth' }); target?.querySelector('h2')?.setAttribute('tabindex', '-1'); target?.querySelector('h2')?.focus({ preventScroll: true }); return; }
      if (d.irReceipt) { receiptSel = d.irReceipt; renderReceipts(); return; }
      if (d.irRemove) { if (await Confirm.ask({ title: 'REMOVE IMPORT', body: 'Remove every record from this import from the workspace? The receipt stays, marked as removed. Saved cases keep their own copies.', confirmLabel: 'REMOVE IMPORT' })) { Ingest.remove(d.irRemove); } return; }
      if (d.irAstext) { Ingest.retryAsText(d.irAstext); return; }
      if (d.irReceiptExport) { const en = Ingest.imports.get(d.irReceiptExport); downloadLocal(JSON.stringify({ product: 'NEXUS VORTEX', kind: 'ingestion-receipt', fileSha256: en.fileSha256, receipt: en.receipt }, null, 2), 'nexus-receipt-' + en.importId + '.json'); return; }
      if (d.irRecords) { const ids = Evidence.all().filter(r => r.importId === d.irRecords).map(r => r.id); setScope('import ' + Ingest.imports.get(d.irRecords)?.fileName, ids); return; }
      if (d.irFfilter) { findingFilter = d.irFfilter; renderFindings(); return; }
      if (d.irFinding) { Investigation.selectFinding(d.irFinding === Investigation.st.finding && t.closest('#irFindingList') ? null : d.irFinding); return; }
      if (d.irAsset) { Investigation.selectAsset(d.irAsset); return; }
      if (d.irEdge) { Investigation.selectEdge(d.irEdge); return; }
      if (d.irRecord != null && t.matches('[data-ir-record]')) { explorer.selected = d.irRecord; if (!explorerCache?.some(r => r.id === d.irRecord)) { explorer.scope = null; explorer.inWindow = false; $('#irInWindow').checked = false; } renderExplorer(); $('#irRecord').scrollIntoView({ block: 'nearest', behavior: REDUCED ? 'auto' : 'smooth' }); return; }
      if (d.irScopeFinding) { const f = Investigation.st.findings.find(x => x.id === d.irScopeFinding); if (f) setScope(f.ruleId + ' ' + f.id + ' supporting records', f.evidenceIds); return; }
      if (d.irScopeAsset) { setScope('records mentioning ' + d.irScopeAsset.replace(/^(dns|user|host):/, ''), recordsForAsset(d.irScopeAsset, Evidence.all()).map(r => r.id)); return; }
      if (d.irScopeEdge) { const ed = Investigation.graph().edges.get(d.irScopeEdge); if (ed) setScope(EDGE_LABEL[ed.kind].toLowerCase() + ' ' + ed.a + ' → ' + ed.b, ed.ids); return; }
      if (t.hasAttribute('data-ir-scope-clear')) { explorer.scope = null; renderExplorer(); return; }
      if (d.irWindowFinding) { const f = Investigation.st.findings.find(x => x.id === d.irWindowFinding); if (f?.window) { const pad = Math.max(30000, (f.window.end - f.window.start) * 0.15); if (Investigation.st.axis !== 'event') Investigation.setAxis('event'); Investigation.setWindow(f.window.start - pad, f.window.end + pad); $('#irTimelinePanel').scrollIntoView({ block: 'start', behavior: REDUCED ? 'auto' : 'smooth' }); } return; }
      if (d.irFocusMesh) { await Router.go('mesh'); return; }
      if (d.irCaseFrom) { caseFromFinding(d.irCaseFrom); return; }
      if (d.irCaseAddFinding) { const f = Investigation.st.findings.find(x => x.id === d.irCaseAddFinding); if (f) attachToCase(f.evidenceIds.map(i => Evidence.get(i)).filter(Boolean), f); return; }
      if (d.irCaseAddAsset) { attachToCase(recordsForAsset(d.irCaseAddAsset, Investigation.visible())); return; }
      if (d.irCaseAddRecord) { const r = Evidence.get(d.irCaseAddRecord); if (r) attachToCase([r]); return; }
      if (d.irCase) { if (caseDirty && caseSel !== d.irCase && !await Confirm.ask({ title: 'DISCARD UNSAVED CHANGES', body: 'The open case has unsaved changes. Open another case and discard them?', confirmLabel: 'DISCARD' })) return; openCase(d.irCase); return; }
      if (t.hasAttribute('data-ir-case-restore')) { if (caseDraft) restoreContext(caseDraft); return; }
      if (t.hasAttribute('data-ir-case-export')) { if (caseDraft) exportDialog(caseDraft); return; }
      if (t.hasAttribute('data-ir-case-delete')) { if (caseDraft && await Confirm.ask({ title: 'DELETE CASE', body: 'Delete “' + caseDraft.title + '” from this browser? Export it first if you need a copy. Imported evidence in this tab is not affected.', confirmLabel: 'DELETE CASE' })) { try { await CaseStore.remove(caseDraft.id); caseSel = null; caseDraft = null; caseDirty = false; renderCases(); } catch (err) { setSaveStatus(err.message, 'alert'); } } return; }
      if (t.hasAttribute('data-ir-dialog-close')) { $('#irDialog').close(); return; }
      if (d.irMesh === 'recenter') { mesh?.recenter(); return; }
    });
    view.addEventListener('keydown', e => { const row = e.target.closest?.('[data-ir-record]'); if (row && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); row.click(); } });
    $('#irDialog').addEventListener('click', e => { if (e.target.closest('[data-ir-dialog-close]')) $('#irDialog').close(); });
    $('#irDialog').addEventListener('keydown', e => e.stopPropagation());
    $('#irDetailClear').addEventListener('click', () => Investigation.clearSelection());
    $('#irNewCase').addEventListener('click', async () => { const c = NVCases.createCase({ title: 'Untitled investigation', window: Investigation.st.window }); caseSel = c.id; caseDraft = c; caseDirty = true; await saveCase(); });
    $('#irCaseFile').addEventListener('change', e => { const f = e.target.files[0]; e.target.value = ''; if (f) importCaseFile(f); });
    let qTimer = null;
    $('#irQuery').addEventListener('input', e => { clearTimeout(qTimer); qTimer = setTimeout(() => { explorer.query = e.target.value; explorer.page = 0; renderExplorer(); }, 180); });
    $('#irKind').addEventListener('change', e => { explorer.kind = e.target.value; explorer.page = 0; renderExplorer(); });
    $('#irQuality').addEventListener('change', e => { explorer.quality = e.target.value; explorer.page = 0; renderExplorer(); });
    $('#irInWindow').addEventListener('change', e => { explorer.inWindow = e.target.checked; explorer.page = 0; renderExplorer(); });
    $('#irPrev').addEventListener('click', () => { explorer.page--; renderExplorer(); });
    $('#irNext').addEventListener('click', () => { explorer.page++; renderExplorer(); });
    $('#irExportRecords').addEventListener('click', () => { const rows = explorerRows(); downloadLocal(JSON.stringify({ product: 'NEXUS VORTEX', kind: 'evidence-records', exportedAt: new Date().toISOString(), note: 'Records as normalised by NEXUS with their original raw text and SHA-256 of each raw line.', count: rows.length, records: rows }, null, 2), 'nexus-records.json'); });
    $('#irClearAll').addEventListener('click', async () => { if (await Confirm.ask({ title: 'CLEAR SESSION EVIDENCE', body: 'Remove all imported records from this tab? Receipts stay, marked cleared. Saved cases are not affected.', confirmLabel: 'CLEAR EVIDENCE' })) Ingest.clearAll(); });
    Ingest.on(what => { schedule('receipts', 'progress', 'chips'); if (what === 'done' || what === 'removed' || what === 'cleared') { schedule('findings', 'explorer', 'mesh', 'timeline', 'detail'); const cur = [...Ingest.imports.values()].pop(); if (what === 'done' && cur?.receipt) announce(cur); } if (what === 'start') Investigation.st.rulesPending = true; if (what === 'rules') schedule('findings', 'detail', 'mesh', 'chips', 'timeline'); });
    Investigation.on(what => {
      if (what === 'evidence') schedule('explorer', 'timeline', 'mesh', 'chips');
      else if (what === 'window') schedule('explorer', 'timeline', 'mesh', 'chips', 'findings', 'detail');
      else schedule('findings', 'detail', 'mesh', 'chips', 'timeline');
    });
    CaseStore.on(() => schedule('cases', 'chips'));
    window.addEventListener('nv:mesh-select', e => {
      if (e.detail?.silent) return;
      const node = e.detail?.node, edge = e.detail?.edge;
      if (edge) Investigation.selectEdge(edge);
      else if (node?.evidence) Investigation.selectAsset(node.assetKey);
      else if (node?.local) Investigation.pickSensor();
    });
    document.addEventListener('click', async e => {
      const t = e.target.closest('.ir-intel button'); if (!t || t.closest('#view-investigate')) return;
      const d = t.dataset;
      if (d.irFinding) Investigation.selectFinding(d.irFinding);
      else if (d.irAsset) Investigation.selectAsset(d.irAsset);
      else if (d.irEdge) Investigation.selectEdge(d.irEdge);
      else if (d.irScopeAsset || d.irScopeEdge) {
        await Router.go('investigate');
        if (d.irScopeAsset) setScope('records mentioning ' + d.irScopeAsset.replace(/^(dns|user|host):/, ''), recordsForAsset(d.irScopeAsset, Evidence.all()).map(r => r.id));
        else { const ed = Investigation.graph().edges.get(d.irScopeEdge); if (ed) setScope(EDGE_LABEL[ed.kind].toLowerCase() + ' ' + ed.a + ' → ' + ed.b, ed.ids); }
      } else if (d.irCaseFrom) { await Router.go('investigate'); caseFromFinding(d.irCaseFrom); }
      else if (d.irWindowFinding) { const f = Investigation.st.findings.find(x => x.id === d.irWindowFinding); if (f?.window) { const pad = Math.max(30000, (f.window.end - f.window.start) * 0.15); Investigation.setWindow(f.window.start - pad, f.window.end + pad); } }
    });
    window.addEventListener('beforeunload', e => { if (caseDirty) { e.preventDefault(); e.returnValue = ''; } });
  }
  function announce(entry) {
    const r = entry.receipt;
    const msg = entry.fileName + ': ' + (STATUS[entry.status] || [entry.status])[0].toLowerCase() + ' — ' + (r.accepted ?? 0).toLocaleString() + ' accepted, ' + (r.rejected ?? 0).toLocaleString() + ' rejected, ' + ((r.duplicates?.withinFile || 0) + (r.duplicates?.acrossImports || 0)).toLocaleString() + ' duplicate' + (r.error ? '. ' + r.error : '') + (r.durationMs != null ? ' (' + r.durationMs.toLocaleString() + ' ms).' : '.');
    say(msg);
    receiptSel = entry.importId;
  }

  /* ---------------------------------------------------------------- lifecycle */
  function mount() {
    if (mounted) return;
    mounted = true;
    const stage = $('#irMeshStage'), canvas = $('#irMeshCanvas');
    if (stage && canvas) mesh = new NeuralMesh(canvas, stage, { mode: 'full', tooltip: $('#irMeshTip'), evidenceNodesOnly: true, onSelect: () => {} });
    MeshBridge.sync();
    render(new Set(['receipts', 'progress', 'findings', 'detail', 'explorer', 'cases', 'chips', 'timeline']));
  }
  function unmount() { if (!mounted) return; mounted = false; mesh?.dispose(); mesh = null; }
  function init() {
    initIntake(); bind();
    timelineMain = Timeline.create(document.querySelector('[data-ir-timeline="full"]'), false);
    const meshView = $('#view-mesh .mesh-layout');
    if (meshView) { const strip = document.createElement('article'); strip.className = 'panel ir-panel ir-mesh-timeline'; strip.setAttribute('aria-label', 'Investigation window'); strip.innerHTML = '<div class="phead"><div class="phead__title"><span class="phead__kicker">EVIDENCE OVERLAY // SHARED WITH INCIDENT RECONSTRUCTION</span><h2>INVESTIGATION WINDOW</h2></div><button class="btn btn--sm" data-route="investigate">RECONSTRUCTION ↗</button></div><div class="pbody" data-ir-timeline="compact"></div>'; meshView.before(strip); timelineMesh = Timeline.create(strip.querySelector('[data-ir-timeline]'), true); }
    Ingest.start();
    CaseStore.init();
    schedule('receipts', 'findings', 'detail', 'explorer', 'cases', 'chips', 'timeline');
  }
  return {
    init, mount, unmount, findingHTML, assetHTML, edgeHTML, legendHTML,
    selectRecord(id) { explorer.selected = id; explorer.scope = null; explorer.inWindow = false; const cb = $('#irInWindow'); if (cb) cb.checked = false; renderExplorer(); },
    importFiles: files => Ingest.enqueue(files), exportRecords: () => $('#irExportRecords').click(), clearSession: () => $('#irClearAll').click(),
    get caseDirty() { return caseDirty; }
  };
})();

/* ============================================================== SECURITY FABRIC
   Mode switch (evidence / training), slim evidence bar on every module, and
   evidence-mode adapters for views that otherwise show simulations. */
const SecurityFabric = (() => {
  const views = ['command', 'mesh', 'feed', 'topology', 'forensics', 'exploit', 'behavior', 'signals', 'lab', 'defense', 'operations'];
  const trainingViews = ['feed', 'topology', 'forensics', 'exploit', 'behavior', 'signals'];
  let mode = 'evidence', health = null;
  const originalUI = new Map();
  function ui(selector, html) { const e = document.querySelector(selector); if (!e) return; if (!originalUI.has(selector)) originalUI.set(selector, e.innerHTML); if (e.innerHTML !== html) e.innerHTML = html; }
  function notify(message) { document.querySelectorAll('[data-fabric-status]').forEach(e => { e.textContent = message; }); }
  function build() {
    for (const route of views) {
      const view = document.getElementById('view-' + route); if (!view) continue;
      const bar = document.createElement('section');
      bar.className = 'fabric-bar'; bar.dataset.fabricRoute = route; bar.setAttribute('aria-label', 'Data mode and evidence status');
      bar.innerHTML = `<div class="fabric-bar__mode" role="group" aria-label="Data mode"><button class="btn btn--sm" data-fabric-mode="evidence">EVIDENCE</button><button class="btn btn--sm" data-fabric-mode="training">TRAINING</button></div><p class="fabric-bar__status" data-fabric-summary></p><button class="btn btn--sm btn--primary" data-route="investigate">INCIDENT RECONSTRUCTION ↗</button><p class="fabric-bar__note" role="status" data-fabric-status></p>`;
      view.prepend(bar);
      if (trainingViews.includes(route)) {
        const content = document.createElement('div'); content.className = 'fabric-content panel'; content.dataset.fabricContent = route;
        bar.after(content);
        const training = document.createElement('div'); training.className = 'fabric-training';
        for (const child of [...view.children]) if (child !== bar && child !== content) training.append(child);
        view.append(training);
      }
    }
  }
  function summary() {
    const w = Investigation.windowRange();
    return mode === 'training' ? 'TRAINING MODE · simulated scenarios and scores; no evidence is shown or altered.' :
      Evidence.count.toLocaleString() + ' records · ' + Investigation.visible().length.toLocaleString() + ' in window · ' + Investigation.st.findings.length + ' finding(s) · ' + CaseStore.list().length + ' saved case(s)' + (w && !w.full ? ' · window ' + UTC.clock(w.start) + '–' + UTC.clock(w.end) + ' UTC' : '');
  }
  let renderQueued = false;
  function render() { if (renderQueued) return; renderQueued = true; requestAnimationFrame(() => { renderQueued = false; renderNow(); }); }
  function renderNow() {
    const active = Router.current();
    document.body.dataset.fabricMode = mode;
    MeshModel.evidenceOnly = mode === 'evidence';
    const modeLabel = document.getElementById('nvMode');
    if (modeLabel) modeLabel.textContent = mode === 'evidence' ? 'EVIDENCE / SOURCE-ATTRIBUTED · LATTICE BACKGROUND SIMULATED' : 'TRAINING / SIMULATED SCENARIOS';
    document.querySelectorAll('[data-fabric-mode]').forEach(b => { const on = b.dataset.fabricMode === mode; b.setAttribute('aria-pressed', String(on)); b.classList.toggle('is-active', on); });
    document.querySelectorAll('[data-fabric-summary]').forEach(e => { e.textContent = summary(); });
    const content = document.querySelector(`[data-fabric-content="${active}"]`);
    if (content && mode === 'evidence') content.innerHTML = adapter(active);
    topbar();
    if (mode === 'evidence') { paintCommand(); paintMesh(); }
    Timeline.drawAll();
  }
  function queueHTML(limit = 12) {
    const list = Investigation.st.findings.filter(f => Investigation.findingInWindow(f)).slice(0, limit);
    return list.map(f => `<button class="fabric-item" data-fabric-finding="${esc(f.id)}"><span class="fabric-tag ${f.severity === 'high' ? 'fabric-high' : ''}">${esc(f.ruleId)} · SEVERITY ${esc(f.severity.toUpperCase())} · CONFIDENCE ${esc(f.confidence.toUpperCase())}</span><strong>${esc(f.title)}</strong><small>${esc(f.summary.slice(0, 220))}</small></button>`).join('') || `<p class="fabric-empty">${Evidence.count ? 'No findings in the current window. This does not establish that the activity was benign.' : 'Import evidence in Incident Reconstruction to evaluate the rules.'}</p>`;
  }
  function adapter(route) {
    if (route === 'topology') {
      const g = Investigation.graph(), list = [...g.nodes.values()].sort((a, b) => b.count - a.count).slice(0, 24);
      if (!list.length) return '<div class="fabric-empty">No observed assets in the current window. Relationships appear only when a record names both ends.</div>';
      const pos = new Map(list.map((a, i) => [a.key, { x: 450 + Math.cos(i / list.length * Math.PI * 2 - Math.PI / 2) * 350, y: 185 + Math.sin(i / list.length * Math.PI * 2 - Math.PI / 2) * 130 }]));
      const lines = [...g.edges.values()].filter(e => pos.has(e.a) && pos.has(e.b)).slice(0, 150);
      return `<h2 class="fabric-bar__title">OBSERVED ASSET RELATIONSHIPS</h2><svg class="fabric-graph" viewBox="0 0 900 370" role="img" aria-label="Observed endpoints and relationships in the current window">${lines.map(e => { const a = pos.get(e.a), b = pos.get(e.b); return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" ${e.kind === 'inferred' ? 'stroke-dasharray="6 5"' : ''}><title>${esc(EDGE_LABEL[e.kind])}: ${esc(edgeBasis(e, g))}</title></line>`; }).join('')}${list.map(a => { const p = pos.get(a.key); const hot = Investigation.st.findings.some(f => f.assets.some(x => x.key === a.key)); return `<g data-fabric-asset="${esc(a.key)}" tabindex="0" role="button" aria-label="Inspect ${esc(a.label)}"><circle cx="${p.x}" cy="${p.y}" r="${hot ? 9 : 6}" class="${hot ? 'fabric-high' : ''}"/><text x="${p.x}" y="${p.y + 23}" text-anchor="middle">${esc(a.label.slice(0, 27))}</text></g>`; }).join('')}</svg><p class="fabric-muted">Top ${list.length} assets by record count in the window. Solid lines are stated by records; dashed lines are inferred by a finding. Magenta nodes appear in findings.</p>`;
    }
    if (route === 'behavior') {
      const counts = new Map(); for (const r of Investigation.visible()) counts.set(r.source, (counts.get(r.source) || 0) + 1);
      const max = Math.max(1, ...counts.values());
      return '<h2 class="fabric-bar__title">OBSERVED RECORD DISTRIBUTION</h2><p class="fabric-muted">Counts per source in the current window. No behavioural baseline is learned or claimed.</p>' + [...counts].sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, n]) => `<div class="fabric-distribution"><span>${esc(k)}</span><meter min="0" max="${max}" value="${n}"></meter><b>${n.toLocaleString()}</b></div>`).join('') + (!counts.size ? '<p class="fabric-empty">Import evidence to see its distribution.</p>' : '');
    }
    if (route === 'signals') return '<h2 class="fabric-bar__title">INDICATOR LOOKUPS</h2><p class="fabric-muted">' + (Operations.companion ? 'Read-only threat-intelligence connectors are configured in Security Operations through the local companion. Files and URLs are never submitted.' : 'Indicator lookups need account credentials, which only the local companion may hold. This public edition does not contact third-party services.') + '</p><button class="btn btn--sm" data-route="operations">SECURITY OPERATIONS ↗</button>';
    if (route === 'forensics') return '<h2 class="fabric-bar__title">ORIGINAL EVIDENCE</h2><p class="fabric-muted">Imported logs are not memory images; memory acquisition needs a separate tool. Latest records in the window:</p>' + Investigation.visible().slice(-8).reverse().map(r => `<button class="fabric-item" data-fabric-record="${esc(r.id)}"><span class="fabric-tag">${esc(r.origin)} / ${esc(r.kind)} / ${esc(r.source)}:${esc(r.line ?? '—')}</span><strong>${esc(r.message.slice(0, 180))}</strong><small>${esc(UTC.full(r.time))}</small></button>`).join('');
    return '<h2 class="fabric-bar__title">FINDINGS IN WINDOW</h2>' + queueHTML();
  }
  function topbar() {
    const set = (id, label, value) => { const b = document.getElementById(id); if (!b) return; const s = b.previousElementSibling; if (!originalUI.has('label:' + id)) originalUI.set('label:' + id, s.textContent); if (mode === 'evidence') { s.textContent = label; b.textContent = value; } };
    if (mode === 'evidence') {
      set('topThreatcon', 'FINDINGS', String(Investigation.st.findings.filter(f => Investigation.findingInWindow(f)).length));
      set('topUplink', 'COMPANION', Operations.companion ? (health ? 'ONLINE' : 'CHECKING') : 'NOT IN PUBLIC EDITION');
      set('topLattice', 'EVIDENCE', Evidence.count.toLocaleString());
      document.getElementById('topUplink').className = Operations.companion && health ? 'safe' : '';
      document.getElementById('topThreatcon').className = Investigation.st.findings.some(f => f.severity === 'high') ? 'alert' : '';
    } else {
      for (const id of ['topThreatcon', 'topUplink', 'topLattice']) { const b = document.getElementById(id); const label = originalUI.get('label:' + id); if (b && label) b.previousElementSibling.textContent = label; }
      document.getElementById('topUplink').className = 'safe'; document.getElementById('topThreatcon').className = 'alert';
      const up = document.getElementById('topUplink'); if (up.textContent !== 'SECURE (SIM)') up.textContent = 'SECURE (SIM)';
    }
  }
  function activityBins() {
    const bins = new Array(24).fill(0), w = Investigation.windowRange(); if (!w) return bins;
    const span = Math.max(1, w.end - w.start), k = Investigation.st.axis === 'event' ? 'time' : 'received';
    for (const r of Investigation.visible()) if (r[k] != null) bins[Math.min(23, Math.floor((r[k] - w.start) / span * 24))]++;
    return bins;
  }
  function paintCommand() {
    if (!MeshModel.evidenceOnly) return;
    const vis = Investigation.visible(), g = Investigation.graph(), findings = Investigation.st.findings.filter(f => Investigation.findingInWindow(f));
    const metrics = [['cmdThreatIndex', 'RECORDS IN WINDOW', vis.length], ['cmdCompromised', 'ASSETS IN WINDOW', g.nodes.size], ['cmdConfidence', 'FINDINGS IN WINDOW', findings.length], ['cmdPacketRate', 'SAVED CASES', CaseStore.list().length]];
    metrics.forEach(([id, label, value], i) => { ui('#' + id, Number(value).toLocaleString()); ui('#view-command .status-tile:nth-child(' + (i + 1) + ') .status-tile__copy>span', label); });
    for (const [id, value] of Object.entries({ cmdLattice: 'EVIDENCE', cmdHostile: String(findings.length), cmdMeshConfidence: 'SOURCE-ATTRIBUTED', cmdNodeCount: String(MeshBridge.stats.shown), cmdFlowCount: String(MeshBridge.stats.edgesShown), cmdUplinkKicker: 'EVIDENCE REVIEW / DETERMINISTIC RULES', cmdUplinkTitle: findings.length + ' FINDING' + (findings.length === 1 ? '' : 'S') + ' IN WINDOW', cmdUplinkText: 'Open Incident Reconstruction to review each finding with its supporting records.', cmdSessionScore: String(CaseStore.list().length), cmdSessionRank: 'CASES', cmdFeedBtnLabel: 'REVIEW' })) ui('#' + id, esc(value));
    ui('#view-command .mesh-overlay__tr', '<span class="mesh-overlay__mag">FINDINGS <b id="cmdHostile">' + findings.length + '</b></span><span class="mesh-overlay__dim">SOURCE-ATTRIBUTED</span>');
    ui('#view-command .mesh-overlay__bl', '<span class="mesh-overlay__live">● EVIDENCE OVERLAY</span><span class="mesh-overlay__dim">NODES <b id="cmdNodeCount">' + MeshBridge.stats.shown + '</b> // RELATIONS <b id="cmdFlowCount">' + MeshBridge.stats.edgesShown + '</b></span>');
    ui('#view-command .mesh-hud-bottom .mesh-legend-mini', '<span><i style="--c:var(--cyan)"></i>INTERNAL</span><span><i style="--c:var(--violet)"></i>EXTERNAL</span><span><i style="--c:var(--acid)"></i>DNS</span><span><i style="--c:var(--amber)"></i>ACCOUNT</span>');
    ui('.packet-panel .phead__kicker', 'SOURCE-ATTRIBUTED / RECORDS IN WINDOW'); ui('.packet-panel h2', 'OBSERVATION STREAM'); ui('.packet-panel .packet-foot', '<span>EVENT RECORDS / NOT PACKET CAPTURE</span>');
    ui('.packet-panel .phead__meta', '<span class="hud-chip">' + vis.length.toLocaleString() + '</span>');
    ui('#packetStream', vis.slice(-12).map(r => `<button class="packet-line fabric-stream-row" data-fabric-record="${esc(r.id)}"><span class="packet-line__time">${esc(UTC.clock(r.time ?? r.received))}</span><span class="packet-line__proto">${esc(r.kind.toUpperCase())}</span><span class="packet-line__text">${esc(r.message.slice(0, 140))}</span></button>`).join('') || '<p class="fabric-empty">Import evidence in Incident Reconstruction.</p>');
    const spark = document.getElementById('behaviorSpark')?.closest('.panel');
    if (spark) { spark.dataset.fabricSpark = ''; ui('[data-fabric-spark] h2', 'RECORDS OVER WINDOW'); ui('[data-fabric-spark] .phead__kicker', '24 BINS / ' + (Investigation.st.axis === 'event' ? 'EVENT TIME' : 'INGESTION TIME')); ui('[data-fabric-spark] .behavior-readout', '<span>SOURCE TIMESTAMPS</span><span>NO LEARNED BASELINE</span>'); ui('#behaviorSparkState', vis.length.toLocaleString()); }
    ui('#intelTicker', '<span>EVIDENCE / ' + Evidence.count.toLocaleString() + ' RECORDS · ' + vis.length.toLocaleString() + ' IN WINDOW · ' + findings.length + ' FINDINGS · NO NETWORK-WIDE COVERAGE IMPLIED · NOTHING UPLOADED</span>');
    ui('#cmdUptime', 'SESSION EVIDENCE');
    ui('#threatQueue', queueHTML(6)); ui('.queue-panel .phead__meta', '<span class="hud-chip">' + findings.length + ' IN WINDOW</span>'); ui('.queue-panel .pfoot', '<span>DETERMINISTIC RULES / NO AUTO-RANKING</span><button class="text-btn" data-route="investigate">OPEN RECONSTRUCTION →</button>');
    const cov = Investigation.st.coverage;
    ui('#view-command .mitre-panel h2', 'RULE COVERAGE'); ui('#view-command .mitre-panel .phead__kicker', NVRules.RULESET); ui('#view-command .mitre-panel .phead__meta', '<span class="hud-chip">' + Object.keys(NVRules.RULES).length + ' RULES</span>');
    ui('#mitreHeat', (cov.length ? cov : Object.keys(NVRules.RULES).map(id => ({ ruleId: id, findings: 0, status: 'not-applicable' }))).map(c => `<div class="mitre-tactic"><div class="mitre-tactic__name">${esc(c.ruleId.replace('NV-', ''))}</div><div class="heat-cell heat-cell--${c.findings ? 4 : c.status === 'evaluated' ? 1 : 0}" title="${esc(c.ruleId + ': ' + c.status)}">${c.findings}</div></div>`).join(''));
    ui('#view-command .mitre-legend', '<span>NOT RUN</span><i></i><i></i><span>EVALUATED</span><i></i><i></i><i></i><span>FINDINGS</span>');
    ui('.timeline-panel h2', 'EVIDENCE TIMELINE'); ui('.timeline-panel .phead__kicker', 'INCIDENT RECONSTRUCTION // FIRST RECORDS IN WINDOW'); ui('#timelineStatus', 'OBSERVED RECORDS');
    const w = Investigation.windowRange();
    ui('#timelinePath', w ? esc(UTC.full(w.start) + ' → ' + UTC.full(w.end)) : 'No timestamped evidence'); ui('#timelineElapsed', w ? 'SPAN ' + esc(UTC.span(w.end - w.start)) : '');
    ui('#lateralTimeline', vis.filter(r => r.time != null).slice(0, 6).map(r => `<div class="timeline-step timeline-step--done"><span class="timeline-step__node"></span><span class="timeline-step__time">${esc(UTC.clock(r.time))}</span><span class="timeline-step__name">${esc(r.kind.toUpperCase())}</span><span class="timeline-step__tag">${esc(r.user || r.src || r.host || r.source)}</span></div>`).join(''));
    ui('#timelineFeed', '<span class="fabric-muted">Order follows recorded timestamps after import assumptions. Sequence is not proof of causation.</span>');
    for (const id of ['quantumCanvas', 'memMiniHex', 'exploitMatrix']) { const panel = document.getElementById(id)?.closest('.panel'); if (panel) panel.dataset.fabricDecorative = ''; }
  }
  function paintMesh() {
    if (!MeshModel.evidenceOnly) return;
    const s = MeshBridge.stats, findings = Investigation.st.findings.filter(f => Investigation.findingInWindow(f));
    for (const [id, label, value, sub] of [['meshStatNodes', 'ASSETS IN WINDOW', s.total, s.total > s.shown ? s.shown + ' DRAWN (CAP ' + MeshBridge.MAX_NODES + ')' : 'ALL DRAWN'], ['meshStatComp', 'FINDINGS IN WINDOW', findings.length, 'DETERMINISTIC RULES'], ['meshStatConf', 'RECORDS IN WINDOW', Investigation.visible().length, Evidence.count.toLocaleString() + ' IN SESSION'], ['meshStatThreat', 'RELATIONSHIPS', s.edgesTotal, s.edgesShown + ' DRAWN']]) {
      ui('#' + id, Number(value).toLocaleString());
      const root = document.getElementById(id)?.parentElement;
      if (root) { root.dataset.fabricStat = id; ui('[data-fabric-stat="' + id + '"]>span', label); ui('[data-fabric-stat="' + id + '"]>.feed-stat__sub', sub); }
    }
    ui('#meshLattice', 'EVIDENCE'); ui('#meshLegend', Workspace.legendHTML());
    ui('#meshDynamicCounts', s.shown + ' ASSETS // ' + s.edgesShown + ' RELATIONS'); ui('#meshSigma', 'N/A'); ui('#meshIntegrity', 'NOT ASSESSED');
    ui('#view-mesh .mesh-overlay__tr', '<span class="mesh-overlay__mag">FINDINGS <b id="meshHostile">' + findings.length + '</b></span><span class="mesh-overlay__dim">EVIDENCE RELATIONSHIPS</span>');
    ui('#view-mesh .mesh-overlay__bl', '<span class="mesh-overlay__live">● EVIDENCE OVERLAY</span><span class="mesh-overlay__dim">' + esc(Investigation.st.focusLabel || 'NO FOCUS') + '</span>');
    ui('#view-mesh .mesh-overlay__br', '<span id="meshDynamicCounts">' + s.shown + ' ASSETS // ' + s.edgesShown + ' RELATIONS</span><span class="mesh-overlay__dim" id="meshFrameMs">FRAME —</span>');
    const bar = document.getElementById('meshIntegrityBar'); if (bar) bar.style.width = '0%';
    ui('#zoneAnalysis', '<p class="fabric-muted">' + s.total + ' assets in the window. Zones and roles require analyst classification; internal/external comes from address ranges only.</p>');
    ui('#view-mesh .mesh-side:last-child .panel:nth-child(2) .pbody .section-rule', 'TRAINING ACTIONS ONLY');
  }
  function bind() {
    document.addEventListener('click', async e => {
      const b = e.target.closest('[data-fabric-mode],[data-fabric-record],[data-fabric-finding],[data-fabric-asset],[data-fabric-selected]'); if (!b) return;
      try {
        if (b.hasAttribute('data-fabric-mode')) {
          mode = b.dataset.fabricMode; document.body.dataset.fabricMode = mode; MeshModel.evidenceOnly = mode === 'evidence';
          if (mode === 'training') for (const [selector, html] of originalUI) { if (selector.startsWith('label:')) continue; const el = document.querySelector(selector); if (el) el.innerHTML = html; }
          const route = Router.current();
          if (['command', 'mesh'].includes(route)) { App.modules[route].unmount(); App.modules[route].mount(); }
          else if (trainingViews.includes(route)) { if (mode === 'training') App.modules[route].mount(); else App.modules[route].unmount(); }
          renderNow(); return;
        }
        if (b.hasAttribute('data-fabric-record')) { await Router.go('investigate'); Workspace.selectRecord(b.dataset.fabricRecord); $('#irRecord')?.scrollIntoView({ block: 'center' }); return; }
        if (b.hasAttribute('data-fabric-finding')) { Investigation.selectFinding(b.dataset.fabricFinding); await Router.go('investigate'); $('#irDetail')?.scrollIntoView({ block: 'start' }); return; }
        if (b.hasAttribute('data-fabric-asset')) { Investigation.selectAsset(b.dataset.fabricAsset); await Router.go('mesh'); return; }
      } catch (error) { notify(error.message); }
    });
    document.addEventListener('keydown', e => { const target = e.target.closest?.('[data-fabric-asset]'); if (target && ['Enter', ' '].includes(e.key)) { e.preventDefault(); target.click(); } });
    window.addEventListener('nv:observations', e => {
      const detail = e.detail, batch = Array.isArray(detail) ? detail : detail?.batch || [];
      if (!batch.length) return;
      const base = Date.now().toString(36);
      const recs = batch.map((r, i) => adapterRecord(r, 'live', base + '-' + i, r.origin === 'LIVE' ? 'LIVE' : 'IMPORT', 'live'));
      const evicted = Evidence.addLive(recs);
      Ingest.addAdapterRows('live', Evidence.all().filter(r => r.importId === 'live'), true);
      if (evicted.length) notify(Evidence.liveEvicted.toLocaleString() + ' older live records were evicted (live retention ' + Evidence.LIMITS.live.toLocaleString() + ').');
    });
    window.addEventListener('nv:source-health', e => { health = e.detail; render(); });
    window.addEventListener('nv:route', () => render());
    window.addEventListener('nv:defense-event', e => {
      const d = e.detail;
      if (['log-ingestion', 'connections', 'scan'].includes(d.kind)) return;
      const raw = JSON.stringify(d);
      const t = Date.parse(d.at);
      const rec = { id: 'local:' + d.id, importId: 'local', source: 'Sentinel Array / ' + d.sensor, line: null, format: 'local-sensor', origin: 'LOCAL', raw, rawSha256: NVCore.sha256Text(raw), rawBytes: NVCore.utf8(raw).length, rawTruncated: false,
        time: Number.isFinite(t) ? t : null, timeQuality: 'observed', timeText: d.at, timeNote: 'Recorded by this browser’s clock when the local sensor observed it.', received: Date.now(), kind: 'sensor',
        src: null, srcPort: null, dst: null, port: null, proto: null, host: null, user: null, outcome: null, authLayer: null, authMethod: null, repeat: 1, query: null, qtype: null, rcode: null, answers: null,
        signature: d.title, severity: d.level === 'high' ? 'high' : d.level === 'review' ? 'medium' : 'info', message: d.title + (d.detail ? ' — ' + d.detail : ''), uid: null, conflicts: null, notes: null, extra: { sensor: d.sensor, kind: d.kind } };
      Evidence.add([rec]);
      Ingest.addAdapterRows('local', [rec]);
    });
  }
  function assetIntelHTML(k) { return `<div class="ir-intel">${Workspace.assetHTML(k, { compact: true })}</div>`; }
  function edgeIntelHTML(k) { return `<div class="ir-intel">${Workspace.edgeHTML(k, { compact: true })}</div>`; }
  /* Mesh view side panel: whichever evidence selection was made last. */
  function intelHTML() {
    if (mode !== 'evidence') return null;
    const st = Investigation.st;
    if (st.pick === 'edge' && st.edge) return edgeIntelHTML(st.edge);
    if (st.pick === 'asset' && st.asset) return assetIntelHTML(st.asset);
    if (st.pick === 'finding') { const f = Investigation.finding(); if (f) return `<div class="ir-intel">${Workspace.findingHTML(f, { compact: true })}</div>`; }
    return null;
  }
  function init() {
    build(); bind(); Workspace.init(); render();
    if (Operations.companion) Operations.checkConnection().catch(e => notify('Companion unavailable: ' + e.message));
  }
  return {
    init, render, notify, paintCommand, paintMesh, activityBins, assetIntelHTML, edgeIntelHTML, intelHTML,
    get mode() { return mode; }, get observations() { return Investigation.visible(); }, get findings() { return Investigation.st.findings; }, get cases() { return CaseStore.list(); }
  };
})();
