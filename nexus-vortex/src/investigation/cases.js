/* NEXUS VORTEX // CASE MODEL
   Versioned case documents, migration from the v1 Security Fabric format,
   and export/verification with SHA-256 digests. Pure: no storage or DOM. */
const NVCases = (() => {
  'use strict';
  const Core = typeof NVCore !== 'undefined' ? NVCore : require('./core.js');
  const SCHEMA = 2;
  const EXPORT_FORMAT = 'nexus-vortex-case';
  const EXPORT_VERSION = 1;
  const LIMITS = { evidence: 2000, rawBytes: 8 * 1048576, notes: 200, noteLength: 8000 };
  const STATUSES = ['open', 'investigating', 'closed'];
  const DISPOSITIONS = ['undetermined', 'true-positive', 'benign-true-positive', 'false-positive', 'insufficient-evidence'];
  const NOTICE = 'SHA-256 digests detect changes made after export. They do not prove who created the evidence or this file: anyone who edits the file can recompute every digest. Compare the file digest with one recorded through a separate trusted channel.';
  const EVIDENCE_FIELDS = ['id', 'importId', 'source', 'line', 'format', 'origin', 'raw', 'rawSha256', 'rawBytes', 'rawTruncated', 'time', 'timeQuality', 'timeText', 'timeNote', 'received', 'kind', 'src', 'srcPort', 'dst', 'port', 'proto', 'host', 'user', 'outcome', 'authLayer', 'authMethod', 'repeat', 'query', 'qtype', 'rcode', 'answers', 'signature', 'severity', 'message', 'uid', 'conflicts', 'notes', 'alsoSeenAt'];
  const FINDING_FIELDS = ['id', 'ruleId', 'ruleVersion', 'ruleset', 'ruleTitle', 'title', 'summary', 'interpretation', 'severity', 'severityBasis', 'confidence', 'confidenceBasis', 'completeness', 'completenessNotes', 'window', 'thresholds', 'evidenceIds', 'evidenceTotal', 'assets', 'edges', 'alternatives', 'missingContext', 'nextSteps', 'corroboration', 'related'];

  const pick = (obj, fields) => { const out = {}; for (const f of fields) if (obj[f] !== undefined) out[f] = structuredCloneSafe(obj[f]); return out; };
  function structuredCloneSafe(v) { return v == null || typeof v !== 'object' ? v : JSON.parse(JSON.stringify(v)); }
  const newId = () => (typeof crypto !== 'undefined' && crypto.randomUUID) ? crypto.randomUUID() : 'case-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
  const iso = ms => new Date(ms).toISOString();

  function snapshotEvidence(r) { return pick(r, EVIDENCE_FIELDS); }
  function snapshotFinding(f) { return pick(f, FINDING_FIELDS); }

  function createCase({ title, finding = null, records = [], sources = [], window = null, now = Date.now() }) {
    const c = {
      schema: SCHEMA, id: newId(), title: String(title || finding?.title || 'Untitled investigation').slice(0, 200),
      createdAt: iso(now), updatedAt: iso(now), status: 'open', disposition: 'undetermined', dispositionNote: '',
      findings: finding ? [snapshotFinding(finding)] : [], evidence: [], sources: [], notes: [],
      window: window || finding?.window || null, assets: finding ? finding.assets.map(a => ({ ...a })) : [],
      history: [{ at: iso(now), action: 'created', detail: finding ? 'From finding ' + finding.id + ' (' + finding.ruleId + ' v' + finding.ruleVersion + ')' : 'Created manually' }]
    };
    attachEvidence(c, records, sources, now);
    return c;
  }
  /* Returns how many were attached; throws when a limit would be exceeded so
     the caller can tell the operator instead of trimming silently. */
  function attachEvidence(c, records, sources = [], now = Date.now()) {
    const have = new Set(c.evidence.map(e => e.id));
    const fresh = records.filter(r => !have.has(r.id));
    if (c.evidence.length + fresh.length > LIMITS.evidence) throw new Error('A case holds at most ' + LIMITS.evidence.toLocaleString() + ' evidence records; this would make ' + (c.evidence.length + fresh.length).toLocaleString() + '. Narrow the selection or split the case.');
    const bytes = c.evidence.reduce((n, e) => n + (e.raw ? e.raw.length : 0), 0) + fresh.reduce((n, e) => n + (e.raw ? e.raw.length : 0), 0);
    if (bytes > LIMITS.rawBytes) throw new Error('Case raw evidence would exceed ' + (LIMITS.rawBytes / 1048576) + ' MiB. Narrow the selection or split the case.');
    for (const r of fresh) c.evidence.push(snapshotEvidence(r));
    const known = new Set(c.sources.map(s => s.importId));
    for (const s of sources) if (s && !known.has(s.importId) && fresh.some(r => r.importId === s.importId)) { c.sources.push({ importId: s.importId, fileName: s.fileName, fileSha256: s.fileSha256 || null, fileSize: s.fileSize ?? null, format: s.format, importedAt: s.startedAt || null, assumptions: s.assumptions || [] }); known.add(s.importId); }
    if (fresh.length) touch(c, 'evidence-attached', fresh.length + ' record(s)', now);
    return fresh.length;
  }
  function addNote(c, text, now = Date.now()) {
    const t = String(text || '').trim();
    if (!t) throw new Error('Note is empty.');
    if (t.length > LIMITS.noteLength) throw new Error('Notes are limited to ' + LIMITS.noteLength + ' characters.');
    if (c.notes.length >= LIMITS.notes) throw new Error('A case holds at most ' + LIMITS.notes + ' notes.');
    c.notes.push({ id: newId(), at: iso(now), text: t });
    touch(c, 'note-added', '', now);
  }
  function setDisposition(c, { status, disposition, note }, now = Date.now()) {
    if (status && !STATUSES.includes(status)) throw new Error('Unknown status ' + status);
    if (disposition && !DISPOSITIONS.includes(disposition)) throw new Error('Unknown disposition ' + disposition);
    const changes = [];
    if (status && status !== c.status) { changes.push('status ' + c.status + ' → ' + status); c.status = status; }
    if (disposition && disposition !== c.disposition) { changes.push('disposition ' + c.disposition + ' → ' + disposition); c.disposition = disposition; }
    if (note != null && note !== c.dispositionNote) { c.dispositionNote = String(note).slice(0, LIMITS.noteLength); changes.push('rationale updated'); }
    if (changes.length) touch(c, 'disposition', changes.join('; '), now);
    return changes.length > 0;
  }
  function touch(c, action, detail, now = Date.now()) {
    c.updatedAt = iso(now);
    c.history.push({ at: iso(now), action, detail });
    if (c.history.length > 500) c.history.splice(0, c.history.length - 500);
  }

  /* ---------------------------------------------------------------- migration */
  function migrateV1(old, now = Date.now()) {
    const evidence = (Array.isArray(old.evidence) ? old.evidence : []).slice(0, LIMITS.evidence).map((e, i) => {
      const raw = typeof e.raw === 'string' ? e.raw : JSON.stringify(e);
      const t = e.time ? Date.parse(e.time) : NaN;
      return {
        id: 'v1:' + (e.id ?? i), importId: 'v1-migrated', source: String(e.source ?? 'unknown'), line: null, format: 'v1-migrated', origin: String(e.origin ?? 'IMPORT'),
        raw, rawSha256: Core.sha256Text(raw), rawBytes: Core.utf8(raw).length, rawTruncated: false,
        time: Number.isFinite(t) ? t : null, timeQuality: Number.isFinite(t) ? 'migrated' : 'missing', timeText: e.time ?? null,
        timeNote: 'Converted from a v1 investigation; how the original timestamp was interpreted was not recorded.',
        received: e.received ? Date.parse(e.received) || null : null, kind: String(e.type ?? 'other'),
        src: e.src || null, srcPort: null, dst: e.dst || null, port: e.port ? Number(e.port) || null : null, proto: null, host: e.host || null, user: null,
        outcome: null, query: null, rcode: null, answers: null, signature: null, severity: e.severity || 'info', message: String(e.message ?? '').slice(0, 600),
        conflicts: null, notes: ['Digest computed during migration, not at original ingestion.'], alsoSeenAt: null
      };
    });
    const status = old.status === 'resolved' ? 'closed' : STATUSES.includes(old.status) ? old.status : 'open';
    return {
      schema: SCHEMA, id: String(old.id), title: String(old.title || 'Migrated investigation').slice(0, 200),
      createdAt: old.created || old.updated || iso(now), updatedAt: old.updated || iso(now), status, disposition: 'undetermined', dispositionNote: '',
      findings: old.rule ? [{ id: 'v1:' + old.rule, ruleId: String(old.rule), ruleVersion: '1 (Security Fabric)', title: 'Legacy rule ' + old.rule, summary: 'Migrated reference; the v1 rule did not record thresholds or windows.', evidenceIds: evidence.map(e => e.id), evidenceTotal: evidence.length, assets: old.assetKey ? [{ key: old.assetKey, kind: 'ip', role: 'v1 asset' }] : [], edges: [] }] : [],
      evidence, sources: [{ importId: 'v1-migrated', fileName: 'v1 investigation storage', fileSha256: null, format: 'v1-migrated', importedAt: null, assumptions: [] }],
      notes: old.notes ? [{ id: newId(), at: old.updated || iso(now), text: String(old.notes).slice(0, LIMITS.noteLength) }] : [],
      window: null, assets: old.assetKey ? [{ key: old.assetKey, kind: 'ip', role: 'v1 asset' }] : [],
      history: [{ at: iso(now), action: 'migrated', detail: 'From nexus-investigations-v1 (schema 1). Original status: ' + (old.status ?? 'unknown') + '.' }]
    };
  }
  function normalizeCase(obj, now = Date.now()) {
    if (!obj || typeof obj !== 'object') throw new Error('Case is not an object.');
    if (obj.schema == null && Array.isArray(obj.evidence) && typeof obj.id === 'string') return migrateV1(obj, now);
    if (obj.schema !== SCHEMA) throw new Error('Unsupported case schema ' + obj.schema + '. This build reads schema 1 and ' + SCHEMA + '.');
    for (const k of ['id', 'title', 'createdAt', 'updatedAt', 'status', 'disposition']) if (typeof obj[k] !== 'string') throw new Error('Case field ' + k + ' is missing or invalid.');
    for (const k of ['evidence', 'findings', 'notes', 'sources', 'history']) if (!Array.isArray(obj[k])) throw new Error('Case field ' + k + ' must be a list.');
    if (!STATUSES.includes(obj.status)) throw new Error('Case status ' + obj.status + ' is not recognised.');
    if (!DISPOSITIONS.includes(obj.disposition)) throw new Error('Case disposition ' + obj.disposition + ' is not recognised.');
    if (obj.evidence.length > LIMITS.evidence) throw new Error('Case has more than ' + LIMITS.evidence + ' evidence records.');
    return obj;
  }

  /* ---------------------------------------------------------------- export */
  function exportPayload(c, { includeRaw = true, exportedAt = iso(Date.now()), app = {} } = {}) {
    const caseCopy = JSON.parse(JSON.stringify(c));
    const checks = [];
    for (const e of caseCopy.evidence) {
      let rawCheck;
      if (!e.raw) rawCheck = 'absent';
      else if (e.rawTruncated) rawCheck = 'excerpt-only';
      else rawCheck = Core.sha256Text(e.raw) === e.rawSha256 ? 'match' : 'mismatch';
      if (!includeRaw && e.raw != null) { e.raw = null; e.rawRedacted = true; rawCheck = 'redacted'; }
      checks.push({ id: e.id, rawSha256: e.rawSha256, rawCheck });
    }
    const body = { format: EXPORT_FORMAT, formatVersion: EXPORT_VERSION, caseSchema: SCHEMA, exportedAt, exportedBy: { app: 'NEXUS VORTEX', edition: app.edition || 'public', version: app.version || 'unknown' }, rawEvidenceIncluded: !!includeRaw, case: caseCopy };
    const contentSha256 = Core.sha256Text(Core.canonicalJSON(body));
    return { ...body, integrity: { algorithm: 'SHA-256', canonicalization: 'NV-CANONICAL-JSON-1 (UTF-8; object keys sorted; no insignificant whitespace) over every top-level member except "integrity" and "notice"', contentSha256, evidence: checks, sources: caseCopy.sources.map(s => ({ importId: s.importId, fileName: s.fileName, fileSha256: s.fileSha256 })) }, notice: NOTICE };
  }
  function buildExport(c, opts = {}) {
    const payload = exportPayload(c, opts);
    const text = JSON.stringify(payload, null, 2) + '\n';
    const mismatched = payload.integrity.evidence.filter(e => e.rawCheck === 'mismatch').map(e => e.id);
    return { text, payload, fileSha256: Core.sha256Text(text), contentSha256: payload.integrity.contentSha256, mismatchedAtExport: mismatched };
  }
  function verifyExport(text) {
    const report = { fileSha256: Core.sha256Text(text), content: 'unchecked', evidence: { matched: 0, mismatched: [], unverifiable: [] }, errors: [], warnings: [], notice: NOTICE };
    let doc;
    try { doc = JSON.parse(text); } catch (e) { report.errors.push('File is not valid JSON: ' + e.message); return { ok: false, report, case: null }; }
    if (!doc || doc.format !== EXPORT_FORMAT) { report.errors.push('Not a NEXUS VORTEX case export (format field is ' + JSON.stringify(doc?.format ?? null) + ').'); return { ok: false, report, case: null }; }
    if (doc.formatVersion !== EXPORT_VERSION) { report.errors.push('Unsupported export version ' + doc.formatVersion + '.'); return { ok: false, report, case: null }; }
    if (!doc.integrity || typeof doc.integrity.contentSha256 !== 'string') { report.content = 'missing'; report.errors.push('The file has no integrity section.'); }
    else {
      const { integrity, notice, ...body } = doc;
      let digest = null;
      try { digest = Core.sha256Text(Core.canonicalJSON(body)); } catch (e) { report.errors.push('Content could not be canonicalised: ' + e.message); }
      report.content = digest === integrity.contentSha256 ? 'match' : 'mismatch';
      report.expectedContentSha256 = integrity.contentSha256; report.actualContentSha256 = digest;
      if (report.content === 'mismatch') report.errors.push('Case content does not match its recorded SHA-256 digest: it changed after export.');
    }
    let c = null;
    try { c = normalizeCase(doc.case); } catch (e) { report.errors.push('Case content is invalid: ' + e.message); }
    if (c) {
      for (const e of c.evidence) {
        if (e.rawRedacted || e.raw == null) { report.evidence.unverifiable.push({ id: e.id, reason: 'Raw line not included in this export.' }); continue; }
        if (e.rawTruncated) { report.evidence.unverifiable.push({ id: e.id, reason: 'Only a ' + Core.RAW_LIMIT + '-character excerpt was retained at ingestion; the digest covers the full original line.' }); continue; }
        if (typeof e.rawSha256 !== 'string') { report.evidence.unverifiable.push({ id: e.id, reason: 'No digest recorded.' }); continue; }
        if (Core.sha256Text(e.raw) === e.rawSha256) report.evidence.matched++; else report.evidence.mismatched.push(e.id);
      }
      if (report.evidence.mismatched.length) report.errors.push(report.evidence.mismatched.length + ' evidence record(s) no longer match the digest recorded at ingestion.');
      if (!doc.rawEvidenceIncluded) report.warnings.push('Exported without raw evidence; only normalised fields and digests are present.');
    }
    return { ok: report.errors.length === 0, report, case: c, exportedAt: doc.exportedAt ?? null };
  }

  /* ---------------------------------------------------------------- sensitivity */
  function sensitivity(c, detect = () => []) {
    const ips = new Set(), internal = new Set(), accounts = new Set(), hosts = new Set(), credentialHits = [];
    let rawCount = 0, rawBytes = 0;
    for (const e of c.evidence) {
      for (const ip of [e.src, e.dst, ...(e.answers || [])]) if (ip) { ips.add(ip); if (Core.isInternal(ip)) internal.add(ip); }
      if (e.user) accounts.add(e.user);
      if (e.host) hosts.add(e.host);
      if (e.raw) { rawCount++; rawBytes += e.raw.length; const cats = detect(e.raw); if (cats.length) credentialHits.push({ id: e.id, categories: cats }); }
    }
    for (const n of c.notes) { const cats = detect(n.text); if (cats.length) credentialHits.push({ id: 'note ' + n.at, categories: cats }); }
    return { evidence: c.evidence.length, rawCount, rawBytes, addresses: ips.size, internalAddresses: internal.size, accounts: [...accounts].slice(0, 50), accountCount: accounts.size, hosts: [...hosts].slice(0, 50), hostCount: hosts.size, notes: c.notes.length, credentialHits };
  }

  return { SCHEMA, EXPORT_FORMAT, EXPORT_VERSION, LIMITS, STATUSES, DISPOSITIONS, NOTICE, createCase, attachEvidence, addNote, setDisposition, migrateV1, normalizeCase, snapshotEvidence, snapshotFinding, buildExport, verifyExport, sensitivity };
})();
if (typeof module !== 'undefined' && module.exports) module.exports = NVCases;
