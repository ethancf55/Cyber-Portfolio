/* NEXUS VORTEX // INGEST ENGINE
   Message-driven import + rule evaluation. Runs inside a blob worker; the
   same factory runs on the main thread when workers are unavailable. */
const NVIngestEngine = (() => {
  'use strict';
  const Core = typeof NVCore !== 'undefined' ? NVCore : require('./core.js');
  const Rules = typeof NVRules !== 'undefined' ? NVRules : require('./rules.js');
  const BATCH = 2000;
  const CHUNK = 256 * 1024;
  const ARRAY_LIMIT = 128 * 1048576;

  function create(post, { yieldFn } = {}) {
    let session = Core.createSession();
    const rows = new Map();
    const jobs = new Map();
    let evalPending = false;
    const pause = yieldFn || (() => new Promise(resolve => setTimeout(resolve, 0)));

    function compact(r) { const { raw, ...rest } = r; return rest; }
    function evaluate() {
      if (evalPending) return;
      evalPending = true;
      Promise.resolve().then(() => {
        evalPending = false;
        const all = [];
        for (const list of rows.values()) for (const r of list) all.push(r);
        const started = Date.now();
        const out = Rules.evaluate(all);
        post({ type: 'rules', findings: out.findings, coverage: out.coverage, ruleset: out.ruleset, durationMs: Date.now() - started, evaluatedRecords: all.length });
      });
    }

    async function runImport(msg) {
      const { jobId, importId, file, fileName, format, options, maxRecords } = msg;
      const job = { cancelled: false };
      jobs.set(jobId, job);
      const started = Date.now();
      const ing = Core.createIngestor({ importId, fileName, fileSize: file.size, format, options, session, maxRecords, received: started });
      const list = [];
      rows.set(importId, list);
      let lastProgress = 0, bytes = 0;
      const progress = force => {
        const now = Date.now();
        if (!force && now - lastProgress < 120) return;
        lastProgress = now;
        post({ type: 'progress', jobId, bytes, total: file.size, lines: ing.lineNo, accepted: ing.receipt.accepted, rejected: ing.receipt.rejected, duplicates: ing.receipt.duplicates.withinFile + ing.receipt.duplicates.acrossImports });
      };
      const flush = () => {
        const d = ing.drain();
        for (let i = 0; i < d.records.length; i += BATCH) {
          const slice = d.records.slice(i, i + BATCH);
          for (const r of slice) list.push(compact(r));
          post({ type: 'batch', jobId, importId, records: slice, annotations: i === 0 ? d.annotations : [], duplicates: i === 0 ? d.duplicates : [] });
        }
        if (!d.records.length && (d.annotations.length || d.duplicates.length)) post({ type: 'batch', jobId, importId, records: [], annotations: d.annotations, duplicates: d.duplicates });
      };
      let receipt;
      try {
        const head = await file.slice(0, 4096).text();
        if (head.replace(/^\ufeff/, '').trimStart().startsWith('[')) {
          if (file.size > ARRAY_LIMIT) throw new Error('JSON array files above 128 MiB are not supported; export the events as one JSON object per line instead.');
          const text = await file.text();
          bytes = file.size;
          let elements;
          try { elements = JSON.parse(text.replace(/^\ufeff/, '')); } catch (e) { throw new Error('JSON array could not be parsed: ' + e.message); }
          if (!Array.isArray(elements)) elements = [elements];
          for (let i = 0; i < elements.length && !job.cancelled && !ing.stopped; i += 1000) {
            ing.pushElements(elements.slice(i, i + 1000));
            flush(); progress(); await pause();
          }
          ing.receipt.bytesRead = file.size;
        } else {
          const decoder = new TextDecoder('utf-8');
          for (let offset = 0; offset < file.size; offset += CHUNK) {
            if (job.cancelled || ing.stopped) break;
            const buf = await file.slice(offset, offset + CHUNK).arrayBuffer();
            bytes = offset + buf.byteLength;
            ing.push(decoder.decode(buf, { stream: offset + CHUNK < file.size }));
            flush(); progress();
            await pause();
            if (msg.paceMs) await new Promise(r => setTimeout(r, msg.paceMs));
          }
          if (!job.cancelled && !ing.stopped) ing.push(decoder.decode());
        }
        receipt = job.cancelled ? ing.cancel() : ing.finish();
        receipt.bytesRead = bytes;
        if (!job.cancelled) flush();
      } catch (e) {
        receipt = ing.seal();
        receipt.status = 'failed';
        receipt.error = String(e.message || e);
      }
      receipt.durationMs = Date.now() - started;
      if (receipt.status === 'cancelled' || receipt.status === 'failed' || receipt.status === 'unrecognized') {
        rows.delete(importId);
        Core.removeImportFromSession(session, importId);
        receipt.rolledBack = receipt.status === 'cancelled' || receipt.status === 'failed' ? receipt.accepted : 0;
      }
      progress(true);
      jobs.delete(jobId);
      post({ type: 'done', jobId, importId, receipt });
      evaluate();
    }

    function handle(msg) {
      if (msg.type === 'import') return runImport(msg);
      if (msg.type === 'cancel') { const job = jobs.get(msg.jobId); if (job) job.cancelled = true; return; }
      if (msg.type === 'remove-import') { rows.delete(msg.importId); Core.removeImportFromSession(session, msg.importId); return evaluate(); }
      if (msg.type === 'add-rows') {
        let list = rows.get(msg.importId); if (!list) rows.set(msg.importId, list = []);
        for (const r of msg.rows) list.push(compact(r));
        if (msg.replace) { rows.set(msg.importId, msg.rows.map(compact)); }
        return evaluate();
      }
      if (msg.type === 'clear') { rows.clear(); session = Core.createSession(); return evaluate(); }
      if (msg.type === 'evaluate') return evaluate();
    }
    return { handle };
  }
  return { create };
})();
if (typeof module !== 'undefined' && module.exports) module.exports = NVIngestEngine;
