/* NEXUS VORTEX // EVIDENCE CORE
   Pure functions shared by the ingest worker, the page, and the Node test suite.
   No DOM, no network, no storage. */
const NVCore = (() => {
  'use strict';

  /* ---------------------------------------------------------------- SHA-256 */
  const K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  const W = new Uint32Array(64);
  const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
  const encoder = new TextEncoder();

  function compress(H, b, o) {
    for (let i = 0; i < 16; i++, o += 4) W[i] = (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3];
    for (let i = 16; i < 64; i++) {
      const x = W[i - 15], y = W[i - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
    }
    let a = H[0], bb = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const t2 = (S0 + ((a & bb) ^ (a & c) ^ (bb & c))) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = bb; bb = a; a = (t1 + t2) | 0;
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + bb) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
  }
  function sha256Bytes(bytes) {
    const H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    const len = bytes.length, full = len - (len % 64);
    for (let o = 0; o < full; o += 64) compress(H, bytes, o);
    const tailLen = len - full, padLen = tailLen < 56 ? 64 : 128;
    const tail = new Uint8Array(padLen);
    tail.set(bytes.subarray(full));
    tail[tailLen] = 0x80;
    const bitsHi = Math.floor(len / 0x20000000), bitsLo = (len << 3) >>> 0;
    tail[padLen - 8] = bitsHi >>> 24; tail[padLen - 7] = bitsHi >>> 16; tail[padLen - 6] = bitsHi >>> 8; tail[padLen - 5] = bitsHi;
    tail[padLen - 4] = bitsLo >>> 24; tail[padLen - 3] = bitsLo >>> 16; tail[padLen - 2] = bitsLo >>> 8; tail[padLen - 1] = bitsLo;
    for (let o = 0; o < padLen; o += 64) compress(H, tail, o);
    let out = '';
    for (let i = 0; i < 8; i++) { const v = H[i]; out += HEX[v >>> 24] + HEX[(v >>> 16) & 255] + HEX[(v >>> 8) & 255] + HEX[v & 255]; }
    return out;
  }
  const utf8 = text => encoder.encode(String(text));
  const sha256Text = text => sha256Bytes(utf8(text));

  /* NV-CANONICAL-JSON-1: object keys sorted by UTF-16 code unit order, no
     whitespace, undefined members omitted, non-finite numbers rejected. */
  function canonicalJSON(value) {
    if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) throw new Error('Non-finite number cannot be canonicalised');
      return JSON.stringify(value);
    }
    if (Array.isArray(value)) return '[' + value.map(v => v === undefined ? 'null' : canonicalJSON(v)).join(',') + ']';
    if (typeof value === 'object') {
      const keys = Object.keys(value).filter(k => value[k] !== undefined).sort();
      return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
    }
    throw new Error('Unsupported value in canonical JSON: ' + typeof value);
  }

  /* ---------------------------------------------------------------- addresses */
  function parseIPv4(s) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
    if (!m) return null;
    const parts = m.slice(1).map(Number);
    if (parts.some(p => p > 255)) return null;
    return parts;
  }
  function normalizeIP(value) {
    if (value == null) return null;
    let s = String(value).trim();
    if (!s || s === '-') return null;
    if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
    if (parseIPv4(s)) return s.split('.').map(Number).join('.');
    if (s.includes(':') && /^[0-9a-f:.]+(%[\w.-]+)?$/i.test(s)) {
      const core = s.split('%')[0].toLowerCase();
      if ((core.match(/::/g) || []).length > 1) return null;
      const groups = core.split(':');
      if (groups.length < 3 || groups.length > 8) return null;
      const last = groups[groups.length - 1];
      if (last.includes('.') && !parseIPv4(last)) return null;
      if (groups.some((g, i) => g.length > 4 && !(i === groups.length - 1 && g.includes('.')))) return null;
      return core;
    }
    return null;
  }
  function ipScope(ip) {
    if (!ip) return 'unknown';
    const v4 = parseIPv4(ip);
    if (v4) {
      const [a, b, c] = v4;
      if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'internal';
      if (a === 100 && b >= 64 && b <= 127) return 'internal';
      if (a === 127) return 'loopback';
      if (a === 169 && b === 254) return 'link-local';
      if (a >= 224 && a <= 239) return 'multicast';
      if (a === 0 || (a === 255 && b === 255)) return 'special';
      if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return 'documentation';
      return 'external';
    }
    if (ip === '::1') return 'loopback';
    if (/^fe[89ab]/.test(ip)) return 'link-local';
    if (/^f[cd]/.test(ip)) return 'internal';
    if (/^ff/.test(ip)) return 'multicast';
    if (/^2001:db8:/.test(ip)) return 'documentation';
    if (ip === '::') return 'special';
    return 'external';
  }
  /* Documentation ranges (RFC 5737 / RFC 3849) behave as external peers. */
  const isInternal = ip => ['internal', 'loopback', 'link-local'].includes(ipScope(ip));
  const isExternal = ip => ['external', 'documentation'].includes(ipScope(ip));
  function normalizePort(value) {
    if (value == null || value === '' || value === '-') return null;
    const n = Number(value);
    return Number.isInteger(n) && n >= 0 && n <= 65535 ? n : undefined;
  }
  function normalizeDomain(value) {
    if (value == null) return null;
    let s = String(value).trim().toLowerCase();
    if (!s || s === '-') return null;
    if (s.endsWith('.')) s = s.slice(0, -1);
    return s.length > 253 ? s.slice(0, 253) : s;
  }

  /* ---------------------------------------------------------------- timestamps */
  const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
  const QUALITY = {
    'explicit-zone': 'Timestamp carries an explicit UTC offset.',
    'epoch': 'Epoch time (UTC by definition).',
    'assumed-zone': 'No UTC offset in the source; the import time zone assumption was applied.',
    'assumed-year': 'Syslog timestamp without a year or zone; the import year and zone assumptions were applied.',
    'date-only': 'Date without a time of day; midnight in the assumed zone was used.',
    'ambiguous': 'Day/month order is ambiguous and the import setting rejects ambiguous dates.',
    'implausible': 'Parsed instant falls outside 1990 to two days after import; treated as unknown.',
    'unparseable': 'Timestamp text could not be interpreted.',
    'missing': 'No timestamp field in this record.'
  };
  const USABLE = new Set(['explicit-zone', 'epoch', 'assumed-zone', 'assumed-year', 'date-only']);
  function defaultOptions(opts = {}) {
    const now = opts.now ?? Date.now();
    return {
      zoneOffsetMinutes: Number.isFinite(opts.zoneOffsetMinutes) ? opts.zoneOffsetMinutes : 0,
      syslogYear: Number.isInteger(opts.syslogYear) ? opts.syslogYear : new Date(now).getUTCFullYear(),
      slashOrder: ['mdy', 'dmy', 'reject'].includes(opts.slashOrder) ? opts.slashOrder : 'reject',
      now, normalized: true
    };
  }
  function build(y, mo, d, h, mi, s, frac, offsetMin, quality, text, opts, note) {
    if (mo < 0 || mo > 11 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60) return { ms: null, quality: 'unparseable', text, note: 'Component out of range' };
    if (s === 60) { s = 59; note = (note ? note + ' ' : '') + 'Leap second 60 recorded as 59.'; }
    const base = Date.UTC(y, mo, d, h, mi, s);
    const check = new Date(base);
    if (check.getUTCDate() !== d || check.getUTCMonth() !== mo) return { ms: null, quality: 'unparseable', text, note: 'Calendar date does not exist' };
    const ms = base + (frac ? Number(('0.' + frac).slice(0, 8)) * 1000 : 0) - offsetMin * 60000;
    return plausible({ ms, quality, text, note: note || null }, opts);
  }
  function plausible(result, opts) {
    if (result.ms == null) return result;
    if (result.ms < Date.UTC(1990, 0, 1) || result.ms > opts.now + 2 * 86400000) return { ms: null, quality: 'implausible', text: result.text, note: 'Parsed as ' + new Date(result.ms).toISOString() };
    return result;
  }
  function parseOffset(z) {
    if (!z) return null;
    if (/^(z|utc|gmt)$/i.test(z)) return 0;
    const m = /^([+-])(\d{2}):?(\d{2})?$/.exec(z);
    if (!m) return undefined;
    const v = Number(m[2]) * 60 + Number(m[3] || 0);
    return v > 18 * 60 ? undefined : (m[1] === '-' ? -v : v);
  }
  function parseTimestamp(value, options) {
    const opts = options?.normalized ? options : defaultOptions(options);
    if (value == null || value === '' || value === '-') return { ms: null, quality: 'missing', text: null, note: null };
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) return { ms: null, quality: 'unparseable', text: String(value), note: null };
      const ms = value > 1e11 ? value : value * 1000;
      return plausible({ ms, quality: 'epoch', text: String(value), note: value > 1e11 ? 'Interpreted as epoch milliseconds.' : 'Interpreted as epoch seconds.' }, opts);
    }
    const text = String(value).trim();
    const s = text;
    let m;
    if ((m = /^(\d{9,10})(?:\.(\d+))?$/.exec(s))) return plausible({ ms: Number(m[1]) * 1000 + (m[2] ? Number('0.' + m[2].slice(0, 6)) * 1000 : 0), quality: 'epoch', text, note: 'Interpreted as epoch seconds.' }, opts);
    if ((m = /^(\d{13})$/.exec(s))) return plausible({ ms: Number(m[1]), quality: 'epoch', text, note: 'Interpreted as epoch milliseconds.' }, opts);
    if ((m = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?)?\s*(Z|UTC|GMT|[+-]\d{2}(?::?\d{2})?)?$/i.exec(s))) {
      const [, y, mo, d, h, mi, sec, frac, zone] = m;
      const off = parseOffset(zone);
      if (off === undefined) return { ms: null, quality: 'unparseable', text, note: 'Invalid UTC offset' };
      if (h == null) return build(+y, +mo - 1, +d, 0, 0, 0, null, off ?? opts.zoneOffsetMinutes, off == null ? 'date-only' : 'explicit-zone', text, opts);
      return build(+y, +mo - 1, +d, +h, +mi, +(sec || 0), frac, off ?? opts.zoneOffsetMinutes, off == null ? 'assumed-zone' : 'explicit-zone', text, opts);
    }
    if ((m = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/.exec(s)) && MONTHS[m[1].toLowerCase()] != null) {
      return build(opts.syslogYear, MONTHS[m[1].toLowerCase()], +m[2], +m[3], +m[4], +m[5], m[6], opts.zoneOffsetMinutes, 'assumed-year', text, opts);
    }
    if ((m = /^(?:[A-Z][a-z]{2},\s*)?(\d{1,2})\s+([A-Z][a-z]{2})\s+(\d{4})\s+(\d{2}):(\d{2})(?::(\d{2}))?\s*(GMT|UTC|Z|[+-]\d{4})?$/i.exec(s)) && MONTHS[m[2].toLowerCase()] != null) {
      const off = parseOffset(m[7]);
      return build(+m[3], MONTHS[m[2].toLowerCase()], +m[1], +m[4], +m[5], +(m[6] || 0), null, off ?? opts.zoneOffsetMinutes, off == null ? 'assumed-zone' : 'explicit-zone', text, opts);
    }
    if ((m = /^(\d{1,2})\/([A-Z][a-z]{2})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?$/.exec(s)) && MONTHS[m[2].toLowerCase()] != null) {
      const off = parseOffset(m[7]);
      return build(+m[3], MONTHS[m[2].toLowerCase()], +m[1], +m[4], +m[5], +m[6], null, off ?? opts.zoneOffsetMinutes, off == null ? 'assumed-zone' : 'explicit-zone', text, opts);
    }
    if ((m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:[ T,]+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?)?\s*(Z|UTC|GMT|[+-]\d{2}:?\d{2})?$/i.exec(s))) {
      let a = +m[1], b = +m[2], order = opts.slashOrder;
      if (a > 12 && b <= 12) order = 'dmy';
      else if (b > 12 && a <= 12) order = 'mdy';
      else if (a <= 12 && b <= 12 && a !== b && order === 'reject') return { ms: null, quality: 'ambiguous', text, note: 'Could be month/day or day/month; set the slash-date order to interpret it.' };
      else if (a === b) order = 'mdy';
      const [mo, d] = order === 'dmy' ? [b, a] : [a, b];
      let h = m[4] != null ? +m[4] : 0;
      if (m[7]) { if (h > 12) return { ms: null, quality: 'unparseable', text, note: 'Hour exceeds 12 with AM/PM' }; h = (h % 12) + (/pm/i.test(m[7]) ? 12 : 0); }
      const off = parseOffset(m[8]);
      const q = m[4] == null ? 'date-only' : off == null ? 'assumed-zone' : 'explicit-zone';
      return build(+m[3], mo - 1, d, h, m[5] != null ? +m[5] : 0, m[6] != null ? +m[6] : 0, null, off ?? opts.zoneOffsetMinutes, q, text, opts, 'Slash date read as ' + order.toUpperCase() + '.');
    }
    return { ms: null, quality: 'unparseable', text: text.slice(0, 120), note: null };
  }

  /* ---------------------------------------------------------------- records */
  const RAW_LIMIT = 16384;
  const LINE_LIMIT = 1048576;
  function newRecord(ctx, line, raw) {
    return {
      id: ctx.importId + ':' + line, importId: ctx.importId, source: ctx.fileName, line, format: ctx.format, origin: ctx.origin || 'IMPORT',
      raw: raw.length > RAW_LIMIT ? raw.slice(0, RAW_LIMIT) : raw, rawSha256: null, rawBytes: 0, rawTruncated: raw.length > RAW_LIMIT,
      time: null, timeQuality: 'missing', timeText: null, timeNote: null, received: ctx.received,
      kind: 'other', src: null, srcPort: null, dst: null, port: null, proto: null, host: null, user: null,
      outcome: null, authLayer: null, authMethod: null, repeat: 1, query: null, qtype: null, rcode: null, answers: null,
      signature: null, severity: 'info', message: '', uid: null, conflicts: null, notes: null, extra: null
    };
  }
  function note(r, text) { (r.notes || (r.notes = [])).push(text); }
  function setTime(r, value, opts, label) {
    const t = parseTimestamp(value, opts);
    r.time = t.ms; r.timeQuality = t.quality; r.timeText = t.text; r.timeNote = t.note ? (label ? label + ': ' : '') + t.note : (label ? 'Event time from ' + label + '.' : null);
    return t;
  }
  function setIP(r, field, value, label) {
    if (value == null || value === '' || value === '-') return;
    const ip = normalizeIP(value);
    if (ip) r[field] = ip; else note(r, label + ' value "' + String(value).slice(0, 80) + '" is not a valid IP address and was ignored.');
  }
  function setPort(r, field, value, label) {
    const p = normalizePort(value);
    if (p === undefined) note(r, label + ' value "' + String(value).slice(0, 40) + '" is not a valid port and was ignored.');
    else r[field] = p;
  }
  /* Additional time fields that disagree with the chosen event time by more
     than one second are recorded as conflicts; the precedence is fixed. */
  function compareTimes(r, candidates, opts) {
    if (r.time == null) return;
    for (const [label, value] of candidates) {
      if (value == null || value === '') continue;
      const t = parseTimestamp(value, opts);
      if (t.ms != null && Math.abs(t.ms - r.time) > 1000) {
        (r.conflicts || (r.conflicts = [])).push({ type: 'timestamp', field: label, value: String(value).slice(0, 80), deltaSeconds: Math.round((t.ms - r.time) / 10) / 100, detail: label + ' differs from the event time by ' + Math.round((t.ms - r.time) / 1000) + ' s; event time kept from the higher-precedence field.' });
      }
    }
  }
  const sevFromNumber = n => n === 1 ? 'high' : n === 2 ? 'medium' : n === 3 ? 'low' : 'info';

  /* ---------------------------------------------------------------- Suricata EVE */
  function dnsAnswers(dns) {
    const ips = [], names = [];
    const push = (type, data) => {
      if (data == null) return;
      const ip = normalizeIP(data);
      if (ip && (type == null || /^(A|AAAA)$/i.test(type))) ips.push(ip);
      else if (/^(CNAME|PTR|NS|MX)$/i.test(type || '')) names.push(normalizeDomain(data));
    };
    if (Array.isArray(dns.answers)) for (const a of dns.answers) push(a.rrtype, a.rdata);
    if (dns.grouped && typeof dns.grouped === 'object') for (const [type, list] of Object.entries(dns.grouped)) if (Array.isArray(list)) for (const v of list) push(type, typeof v === 'object' ? v.rdata ?? v.value : v);
    if (dns.rdata != null) push(dns.rrtype, dns.rdata);
    return { ips: [...new Set(ips)], names: [...new Set(names.filter(Boolean))] };
  }
  function parseEve(text, line, ctx) {
    let o;
    try { o = JSON.parse(text); } catch (e) { return { reject: 'Invalid JSON: ' + String(e.message).slice(0, 120) }; }
    if (!o || typeof o !== 'object' || Array.isArray(o)) return { reject: 'EVE line is not a JSON object' };
    if (typeof o.event_type !== 'string' || !o.event_type) return { reject: 'EVE record lacks event_type' };
    const r = newRecord(ctx, line, text);
    const type = o.event_type;
    setIP(r, 'src', o.src_ip, 'src_ip'); setIP(r, 'dst', o.dest_ip, 'dest_ip');
    setPort(r, 'srcPort', o.src_port, 'src_port'); setPort(r, 'port', o.dest_port, 'dest_port');
    r.proto = o.proto ? String(o.proto).toLowerCase().slice(0, 16) : null;
    r.host = o.host ? String(o.host).slice(0, 253) : null;
    r.uid = o.flow_id != null ? 'eve-flow:' + String(o.flow_id) : null;
    if (type === 'flow' && o.flow?.start) {
      setTime(r, o.flow.start, ctx.opts, 'flow.start');
      if (r.time == null) setTime(r, o.timestamp, ctx.opts, 'timestamp');
      else note(r, 'Flow start used as event time; EVE timestamp ' + String(o.timestamp ?? 'absent').slice(0, 40) + ' records when the flow was logged.');
    } else {
      setTime(r, o.timestamp, ctx.opts, 'timestamp');
    }
    compareTimes(r, [['@timestamp', o['@timestamp']], ['event.created', o.event?.created]], ctx.opts);
    if (type === 'alert') {
      r.kind = 'alert'; r.signature = String(o.alert?.signature ?? 'Unnamed alert').slice(0, 300);
      r.severity = sevFromNumber(Number(o.alert?.severity));
      r.extra = { signatureId: o.alert?.signature_id ?? null, category: o.alert?.category ?? null, action: o.alert?.action ?? null };
      r.message = 'Suricata alert: ' + r.signature;
    } else if (type === 'dns') {
      const dns = o.dns || {};
      r.kind = 'dns';
      const isAnswer = dns.type === 'answer' || dns.type === 'response';
      let query = dns.rrname, qtype = dns.rrtype;
      if (Array.isArray(dns.queries) && dns.queries[0]) { query = dns.queries[0].rrname; qtype = dns.queries[0].rrtype; }
      r.query = normalizeDomain(query); r.qtype = qtype ? String(qtype).toUpperCase().slice(0, 12) : null;
      if (isAnswer) {
        [r.src, r.dst] = [r.dst, r.src]; [r.srcPort, r.port] = [r.port, r.srcPort];
        note(r, 'EVE DNS response: src/dest swapped so src is the client and dst the resolver.');
        r.rcode = dns.rcode ? String(dns.rcode).toUpperCase().slice(0, 16) : 'NOERROR';
        const a = dnsAnswers(dns);
        r.answers = a.ips.length ? a.ips : null;
        r.extra = a.names.length ? { cnames: a.names } : null;
      }
      r.message = 'DNS ' + (isAnswer ? 'response' : 'query') + ' ' + (r.qtype || '') + ' ' + (r.query || '(no name)') + (isAnswer ? ' → ' + (r.answers ? r.answers.join(', ') : r.rcode) : '');
    } else if (type === 'flow') {
      r.kind = 'conn';
      const f = o.flow || {};
      r.extra = { bytesToServer: f.bytes_toserver ?? null, bytesToClient: f.bytes_toclient ?? null, state: f.state ?? null, end: f.end ?? null };
      r.message = 'Flow ' + (r.proto || '') + ' ' + (r.src || '?') + ':' + (r.srcPort ?? '?') + ' → ' + (r.dst || '?') + ':' + (r.port ?? '?');
    } else if (type === 'http') {
      r.kind = 'http';
      const h = o.http || {};
      r.extra = { hostname: h.hostname ?? null, url: h.url ?? null, method: h.http_method ?? null, status: h.status ?? null, userAgent: h.http_user_agent ?? null };
      r.message = 'HTTP ' + (h.http_method || '') + ' ' + String(h.hostname || r.dst || '').slice(0, 200) + String(h.url || '').slice(0, 300);
    } else if (type === 'tls') {
      r.kind = 'tls';
      r.extra = { sni: o.tls?.sni ?? null, version: o.tls?.version ?? null };
      r.message = 'TLS ' + String(o.tls?.sni || r.dst || '').slice(0, 253);
    } else if (type === 'ssh') {
      r.kind = 'ssh'; r.message = 'SSH session ' + (r.src || '?') + ' → ' + (r.dst || '?');
    } else {
      r.kind = 'other'; r.message = 'EVE ' + type.slice(0, 40) + (r.src ? ' ' + r.src + ' → ' + (r.dst || '?') : '');
    }
    r.extra = { ...(r.extra || {}), eventType: type };
    return { record: r };
  }

  /* ---------------------------------------------------------------- Zeek */
  function zeekPathFromName(name) {
    const m = /(?:^|[\/_.-])(conn|dns|http|ssl|ssh|notice|files|weird|x509|dhcp|smtp)(?:[._-]|\.log|$)/i.exec(name || '');
    return m ? m[1].toLowerCase() : null;
  }
  function inferZeekPath(o) {
    if (o._path) return String(o._path);
    if ('query' in o && ('rcode_name' in o || 'qtype_name' in o)) return 'dns';
    if ('conn_state' in o || 'orig_bytes' in o || 'history' in o) return 'conn';
    if ('server_name' in o || 'ssl_history' in o) return 'ssl';
    if ('method' in o && 'uri' in o) return 'http';
    if ('auth_success' in o) return 'ssh';
    return null;
  }
  function zeekRecord(o, path, text, line, ctx) {
    const r = newRecord(ctx, line, text);
    setTime(r, o.ts, ctx.opts, 'ts');
    setIP(r, 'src', o['id.orig_h'], 'id.orig_h'); setIP(r, 'dst', o['id.resp_h'], 'id.resp_h');
    setPort(r, 'srcPort', o['id.orig_p'], 'id.orig_p'); setPort(r, 'port', o['id.resp_p'], 'id.resp_p');
    r.proto = o.proto ? String(o.proto).toLowerCase().slice(0, 16) : null;
    r.uid = o.uid ? 'zeek:' + String(o.uid).slice(0, 64) : null;
    compareTimes(r, [['@timestamp', o['@timestamp']]], ctx.opts);
    path = path || inferZeekPath(o) || 'unknown';
    if (path === 'conn') {
      r.kind = 'conn';
      r.extra = { state: o.conn_state ?? null, duration: o.duration ?? null, origBytes: o.orig_bytes ?? null, respBytes: o.resp_bytes ?? null, service: o.service ?? null };
      r.message = 'Connection ' + (r.proto || '') + ' ' + (r.src || '?') + ':' + (r.srcPort ?? '?') + ' → ' + (r.dst || '?') + ':' + (r.port ?? '?') + (o.conn_state ? ' ' + String(o.conn_state).slice(0, 12) : '');
    } else if (path === 'dns') {
      r.kind = 'dns';
      r.query = normalizeDomain(o.query); r.qtype = o.qtype_name ? String(o.qtype_name).toUpperCase().slice(0, 12) : null;
      r.rcode = o.rcode_name ? String(o.rcode_name).toUpperCase().slice(0, 16) : null;
      const answers = Array.isArray(o.answers) ? o.answers : typeof o.answers === 'string' && o.answers ? o.answers.split(ctx.setSeparator || ',') : [];
      const ips = [], names = [];
      for (const a of answers) { const ip = normalizeIP(a); if (ip) ips.push(ip); else if (a) names.push(normalizeDomain(a)); }
      r.answers = ips.length ? [...new Set(ips)] : null;
      if (names.length) r.extra = { cnames: names.filter(Boolean).slice(0, 20) };
      r.message = 'DNS ' + (r.qtype || '') + ' ' + (r.query || '(no name)') + ' → ' + (r.answers ? r.answers.join(', ') : (r.rcode || 'no response logged'));
    } else if (path === 'http') {
      r.kind = 'http';
      r.extra = { hostname: o.host ?? null, url: o.uri ?? null, method: o.method ?? null, status: o.status_code ?? null, userAgent: o.user_agent ?? null };
      r.message = 'HTTP ' + String(o.method || '') + ' ' + String(o.host || r.dst || '').slice(0, 200) + String(o.uri || '').slice(0, 300);
    } else if (path === 'ssl') {
      r.kind = 'tls'; r.extra = { sni: o.server_name ?? null, version: o.version ?? null };
      r.message = 'TLS ' + String(o.server_name || r.dst || '').slice(0, 253);
    } else if (path === 'ssh') {
      r.kind = 'ssh';
      if (o.auth_success === true || o.auth_success === 'T') r.outcome = 'success';
      else if (o.auth_success === false || o.auth_success === 'F') r.outcome = 'failure';
      r.message = 'SSH ' + (r.src || '?') + ' → ' + (r.dst || '?') + (r.outcome ? ' auth ' + r.outcome : '') + ' (Zeek does not record the account)';
    } else {
      r.kind = 'other'; r.message = 'Zeek ' + String(path).slice(0, 24) + ' record';
    }
    r.extra = { ...(r.extra || {}), zeekPath: path };
    return { record: r };
  }
  function createZeekTSV(ctx) {
    let fields = null, separator = '\t', unset = '-', empty = '(empty)', path = zeekPathFromName(ctx.fileName);
    return {
      line(text, line) {
        if (text.startsWith('#')) {
          if (text.startsWith('#separator ')) separator = text.slice(11).replace(/\\x([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
          else if (text.startsWith('#fields')) fields = text.split(separator).slice(1);
          else if (text.startsWith('#set_separator')) ctx.setSeparator = text.split(separator)[1] || ',';
          else if (text.startsWith('#unset_field')) unset = text.split(separator)[1] ?? '-';
          else if (text.startsWith('#empty_field')) empty = text.split(separator)[1] ?? '(empty)';
          else if (text.startsWith('#path')) path = text.split(separator)[1] || path;
          return { meta: true };
        }
        if (!fields) return { reject: 'Zeek data line before a #fields header' };
        const values = text.split(separator);
        if (values.length !== fields.length) return { reject: 'Expected ' + fields.length + ' tab-separated fields, found ' + values.length };
        const o = {};
        fields.forEach((k, i) => { const v = values[i]; o[k] = v === unset ? null : v === empty ? '' : v; });
        const result = zeekRecord(o, path, text, line, ctx);
        if (result.record) result.dedupScope = path + '|' + fields.join(',');
        return result;
      }
    };
  }
  function parseZeekJSON(text, line, ctx) {
    let o;
    try { o = JSON.parse(text); } catch (e) { return { reject: 'Invalid JSON: ' + String(e.message).slice(0, 120) }; }
    if (!o || typeof o !== 'object' || Array.isArray(o)) return { reject: 'Zeek JSON line is not an object' };
    if (o.ts == null && o['id.orig_h'] == null) return { reject: 'Zeek JSON record lacks ts and id.orig_h' };
    return zeekRecord(o, inferZeekPath(o) || zeekPathFromName(ctx.fileName), text, line, ctx);
  }

  /* ---------------------------------------------------------------- syslog auth */
  const SYSLOG_3164 = /^(?:<(\d{1,3})>)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(\S+)\s+([^\s:\[]+)(?:\[(\d+)\])?:\s?(.*)$/;
  const SYSLOG_ISO = /^(?:<(\d{1,3})>)?(?:1\s+)?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+([^\s:\[]+)(?:\[(\d+)\])?:?\s(?:(?:-|\S+)\s+(?:-|\S+)\s+(?:-|\[[^\]]*\])\s+)?(.*)$/;
  function classifyAuth(r, program, msg) {
    let m;
    const prog = program.toLowerCase();
    const repeat = /^message repeated (\d+) times: \[\s*(.*)\]$/.exec(msg);
    if (repeat) { r.repeat = Math.min(100000, Number(repeat[1])); msg = repeat[2]; note(r, 'Syslog compressed ' + r.repeat + ' identical messages into this line.'); }
    if ((m = /^Failed (\S+) for (invalid user )?(.+?) from (\S+) port (\d+)/.exec(msg))) {
      r.kind = 'auth'; r.outcome = 'failure'; r.authLayer = 'service'; r.authMethod = m[1]; r.user = m[3].slice(0, 128);
      setIP(r, 'src', m[4], 'source address'); setPort(r, 'srcPort', m[5], 'source port');
      if (m[2]) r.extra = { invalidUser: true };
    } else if ((m = /^Accepted (\S+) for (.+?) from (\S+) port (\d+)/.exec(msg))) {
      r.kind = 'auth'; r.outcome = 'success'; r.authLayer = 'service'; r.authMethod = m[1]; r.user = m[2].slice(0, 128);
      setIP(r, 'src', m[3], 'source address'); setPort(r, 'srcPort', m[4], 'source port');
    } else if ((m = /^Invalid user (.*?) from (\S+)(?: port (\d+))?/.exec(msg))) {
      r.kind = 'auth'; r.outcome = 'notice'; r.authLayer = 'service'; r.user = m[1].slice(0, 128);
      setIP(r, 'src', m[2], 'source address');
      note(r, 'Pre-authentication notice; the matching "Failed …" line, if present, is counted as the failure.');
    } else if ((m = /pam_unix\(([^:)]+):auth\): authentication failure;(.*)$/.exec(msg))) {
      r.kind = 'auth'; r.outcome = 'failure'; r.authLayer = 'pam'; r.authMethod = 'pam:' + m[1];
      const rhost = /rhost=(\S*)/.exec(m[2]), user = /\buser=(\S+)/.exec(m[2]);
      if (rhost && rhost[1]) setIP(r, 'src', rhost[1], 'rhost');
      if (user) r.user = user[1].slice(0, 128);
    } else if ((m = /^pam_unix\(([^:)]+):session\): session opened for user (\S+)/.exec(msg))) {
      r.kind = 'auth'; r.outcome = 'session'; r.authLayer = 'pam'; r.user = m[2].replace(/\(.*$/, '').slice(0, 128);
    } else if (prog === 'sudo' && (m = /^\s*(\S+) : .*?USER=(\S+) ; COMMAND=(.*)$/.exec(msg))) {
      r.kind = 'auth'; r.outcome = 'privilege'; r.authLayer = 'service'; r.user = m[1].slice(0, 128); r.extra = { runAs: m[2].slice(0, 64), command: m[3].slice(0, 500) };
    } else if (/^Connection (?:closed|reset) by (?:authenticating|invalid) user/.test(msg) || /^Disconnected from/.test(msg)) {
      r.kind = 'auth'; r.outcome = 'notice'; r.authLayer = 'service';
      const ip = /(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+:[0-9a-f:]+)\s+port/i.exec(msg); if (ip) setIP(r, 'src', ip[1], 'source address');
    } else {
      r.kind = 'syslog';
    }
    r.message = (program + ': ' + msg).slice(0, 600);
  }
  function parseSyslog(text, line, ctx) {
    let m = SYSLOG_3164.exec(text), iso = false;
    if (!m) { m = SYSLOG_ISO.exec(text); iso = true; }
    if (!m) return { reject: 'Not a recognised syslog line (expected "Mon DD HH:MM:SS host program[pid]: message" or an ISO 8601 prefix)' };
    const r = newRecord(ctx, line, text);
    setTime(r, m[2], ctx.opts, iso ? 'syslog ISO timestamp' : 'syslog RFC 3164 timestamp');
    r.host = m[3].slice(0, 253);
    if (m[1] != null) { const sev = Number(m[1]) % 8; r.severity = sev <= 3 ? 'high' : sev === 4 ? 'medium' : 'info'; }
    classifyAuth(r, m[4], m[6] ?? '');
    r.extra = { ...(r.extra || {}), program: m[4].slice(0, 64), pid: m[5] ?? null };
    return { record: r };
  }

  /* ---------------------------------------------------------------- auth CSV */
  const CSV_COLUMNS = {
    time: ['timestamp', 'time', 'datetime', 'date', 'event_time', 'eventtime', '@timestamp', 'createddatetime', '_time', 'published', 'time_generated', 'timegenerated'],
    user: ['user', 'username', 'user_name', 'account', 'principal', 'userprincipalname', 'actor', 'target_user', 'login', 'email'],
    src: ['src_ip', 'source_ip', 'ip', 'ipaddress', 'ip_address', 'client_ip', 'clientip', 'remote_ip', 'src', 'callerip', 'client_address'],
    outcome: ['result', 'outcome', 'status', 'success', 'event_outcome', 'action', 'resulttype', 'auth_result'],
    host: ['app', 'application', 'host', 'target', 'service', 'resource', 'appdisplayname', 'computer'],
    id: ['event_id', 'id', 'eventid', 'record_id', 'uuid', 'correlation_id', 'requestid', 'uuid']
  };
  const SECONDARY_TIME = ['received_time', 'ingest_time', 'logged_at', 'created', 'event_created'];
  function mapOutcome(v) {
    const s = String(v ?? '').trim().toLowerCase();
    if (/^(success|succeeded|successful|ok|true|allow|allowed|accepted|pass|passed|0|login_success|signin_success)$/.test(s)) return 'success';
    if (/^(fail|failed|failure|false|deny|denied|error|invalid|rejected|blocked|login_failure|bad_password|50126|50053)$/.test(s)) return 'failure';
    return null;
  }
  function splitCSVRecord(text) {
    const out = []; let cell = '', quoted = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (quoted) { if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else quoted = false; } else cell += c; }
      else if (c === '"' && cell === '') quoted = true;
      else if (c === ',') { out.push(cell); cell = ''; }
      else cell += c;
    }
    if (quoted) return null;
    out.push(cell.replace(/\r$/, ''));
    return out;
  }
  const CSV_MAX_PHYSICAL_LINES = 20;
  function createAuthCSV(ctx) {
    let headers = null, map = null, pending = [];
    const quotes = s => { let n = 0; for (let i = 0; i < s.length; i++) if (s[i] === '"') n++; return n; };
    function header(cells) {
      headers = cells.map(h => h.trim());
      const lower = headers.map(h => h.toLowerCase().replace(/^\ufeff/, ''));
      map = {};
      for (const [key, names] of Object.entries(CSV_COLUMNS)) { const idx = lower.findIndex(h => names.includes(h)); if (idx >= 0) map[key] = idx; }
      map.secondaryTimes = lower.map((h, i) => SECONDARY_TIME.includes(h) && i !== map.time ? i : -1).filter(i => i >= 0);
      const missing = ['time', 'outcome'].filter(k => map[k] == null);
      if (map.user == null && map.src == null) missing.push('user or source IP');
      ctx.columnMapping = Object.fromEntries(Object.entries(map).filter(([k]) => k !== 'secondaryTimes').map(([k, i]) => [k, headers[i]]));
      if (missing.length) return { fatal: 'Authentication CSV is missing required column(s): ' + missing.join(', ') + '. Found: ' + headers.join(', ').slice(0, 300) };
      return { meta: true };
    }
    /* A record may span physical lines inside quotes. An unbalanced quote is
       abandoned after CSV_MAX_PHYSICAL_LINES: only its first line is rejected
       and the following lines are parsed again on their own. */
    function feed(text, line, results) {
      pending.push([text, line]);
      const joined = pending.map(p => p[0]).join('\n');
      if (quotes(joined) % 2 === 1) {
        if (pending.length > CSV_MAX_PHYSICAL_LINES || joined.length > LINE_LIMIT) {
          const [first, ...rest] = pending; pending = [];
          results.push({ reject: 'Unbalanced quote in CSV record; the record was abandoned and following lines re-read individually', line: first[1], original: first[0] });
          for (const [t, l] of rest) feed(t, l, results);
        }
        return;
      }
      const recordLine = pending[0][1]; pending = [];
      results.push(row(joined, recordLine));
    }
    function row(recordText, recordLine) {
        const cells = splitCSVRecord(recordText);
        if (!cells) return { reject: 'Malformed CSV quoting', line: recordLine, original: recordText };
        if (!headers) { const h = header(cells); return { ...h, line: recordLine }; }
        if (cells.length !== headers.length) return { reject: 'Expected ' + headers.length + ' columns, found ' + cells.length, line: recordLine, original: recordText };
        const r = newRecord(ctx, recordLine, recordText);
        r.kind = 'auth'; r.authLayer = 'service';
        setTime(r, cells[map.time], ctx.opts, headers[map.time]);
        compareTimes(r, map.secondaryTimes.map(i => [headers[i], cells[i]]), ctx.opts);
        if (map.user != null && cells[map.user]) r.user = cells[map.user].trim().slice(0, 128);
        if (map.src != null) setIP(r, 'src', cells[map.src], headers[map.src]);
        if (map.host != null && cells[map.host]) r.host = cells[map.host].trim().slice(0, 253);
        r.outcome = mapOutcome(cells[map.outcome]);
        if (!r.outcome) { r.outcome = 'unknown'; note(r, 'Outcome value "' + String(cells[map.outcome]).slice(0, 40) + '" is not recognised as success or failure.'); }
        if (map.id != null && cells[map.id]) r.uid = 'csv-id:' + cells[map.id].trim().slice(0, 128);
        r.message = 'Authentication ' + r.outcome + ' for ' + (r.user || '(no account)') + (r.src ? ' from ' + r.src : '') + (r.host ? ' to ' + r.host : '');
        return { record: r, line: recordLine, original: recordText };
    }
    return {
      line(text, line) { const results = []; feed(text, line, results); return results; },
      end() {
        if (!pending.length) return null;
        const [first, ...rest] = pending; pending = [];
        const results = [{ reject: 'File ended inside a quoted CSV field', line: first[1], original: first[0] }];
        for (const [t, l] of rest) feed(t, l, results);
        return results;
      }
    };
  }

  /* ---------------------------------------------------------------- Windows auth JSON */
  const WIN_EVENTS = { 4624: 'success', 4625: 'failure', 4771: 'failure', 4776: null, 4648: 'notice', 4634: 'notice' };
  function parseWindowsAuth(text, line, ctx, element) {
    let o = element;
    if (!o) { try { o = JSON.parse(text); } catch (e) { return { reject: 'Invalid JSON: ' + String(e.message).slice(0, 120) }; } }
    if (!o || typeof o !== 'object' || Array.isArray(o)) return { reject: 'Windows event is not a JSON object' };
    const data = o.EventData || o.Properties || o;
    const id = Number(o.EventID ?? o.Id ?? o.event_id ?? o.System?.EventID);
    if (!Number.isInteger(id)) return { reject: 'Windows event lacks a numeric EventID' };
    const r = newRecord(ctx, line, text);
    r.kind = 'auth'; r.authLayer = 'service';
    setTime(r, o.TimeCreated?.SystemTime ?? o.TimeCreated ?? o['@timestamp'] ?? o.timestamp, ctx.opts, 'TimeCreated');
    r.user = data.TargetUserName ? String(data.TargetUserName).slice(0, 128) : null;
    setIP(r, 'src', data.IpAddress, 'IpAddress');
    r.host = o.Computer || o.MachineName ? String(o.Computer || o.MachineName).slice(0, 253) : null;
    if (id === 4776) r.outcome = String(data.Status ?? '0x0').toLowerCase() === '0x0' ? 'success' : 'failure';
    else r.outcome = WIN_EVENTS[id] ?? 'notice';
    r.authMethod = 'windows:' + id + (data.LogonType != null ? ' type ' + data.LogonType : '');
    r.uid = o.RecordId != null ? 'win-record:' + (r.host || '') + ':' + o.RecordId : null;
    r.message = 'Windows event ' + id + ': logon ' + r.outcome + ' for ' + (r.user || '(no account)') + (r.src ? ' from ' + r.src : '');
    return { record: r };
  }

  /* ---------------------------------------------------------------- generic text */
  const LEADING_TS = /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{10}(?:\.\d+)?)\b/;
  function parseText(text, line, ctx) {
    const r = newRecord(ctx, line, text);
    const m = LEADING_TS.exec(text);
    if (m) setTime(r, m[1], ctx.opts, 'leading timestamp');
    r.kind = 'text'; r.message = text.slice(0, 600);
    return { record: r };
  }

  /* ---------------------------------------------------------------- detection */
  const FORMATS = {
    'suricata-eve': 'Suricata EVE JSON',
    'zeek-tsv': 'Zeek TSV log',
    'zeek-json': 'Zeek JSON log',
    'syslog-auth': 'Syslog / authentication log',
    'auth-csv': 'Authentication CSV export',
    'windows-auth-json': 'Windows Security logon events (JSON)',
    'text': 'Generic text lines (unverified)'
  };
  function detectFormat(sample, fileName = '') {
    const lines = sample.split(/\r\n|\n|\r/).map(l => l.replace(/^\ufeff/, '')).filter(l => l.trim());
    if (!lines.length) return { format: null, reason: 'File is empty.' };
    if (lines.some(l => l.startsWith('#separator') || l.startsWith('#fields'))) return { format: 'zeek-tsv', reason: 'Zeek #separator/#fields header present.' };
    const head = lines.slice(0, 40);
    const trimmed = sample.replace(/^\ufeff/, '').trimStart();
    if (trimmed.startsWith('[')) {
      const elem = /\{[^{}]*\}/.exec(trimmed);
      if (elem && /"EventID"|"TargetUserName"/.test(elem[0])) return { format: 'windows-auth-json', container: 'array', reason: 'JSON array whose elements carry EventID/TargetUserName.' };
      if (elem && /"event_type"/.test(elem[0])) return { format: 'suricata-eve', container: 'array', reason: 'JSON array whose elements carry event_type.' };
      if (elem && /"id\.orig_h"/.test(elem[0])) return { format: 'zeek-json', container: 'array', reason: 'JSON array whose elements carry id.orig_h.' };
      return { format: null, reason: 'JSON array without recognised EVE, Zeek or Windows logon fields.' };
    }
    let eve = 0, zeek = 0, win = 0, json = 0, sys = 0;
    for (const l of head) {
      if (l.trimStart().startsWith('{')) {
        try {
          const o = JSON.parse(l); json++;
          if (o && typeof o.event_type === 'string') eve++;
          else if (o && ('id.orig_h' in o || ('uid' in o && 'ts' in o))) zeek++;
          else if (o && (o.EventID != null || o.TargetUserName != null || o.EventData?.TargetUserName != null)) win++;
        } catch { /* counted as non-JSON */ }
      } else if (SYSLOG_3164.test(l) || SYSLOG_ISO.test(l)) sys++;
    }
    const best = Math.max(eve, zeek, win, sys);
    if (best && best === eve) return { format: 'suricata-eve', reason: eve + ' of the first ' + head.length + ' lines are JSON objects with event_type.' };
    if (best && best === zeek) return { format: 'zeek-json', reason: zeek + ' of the first ' + head.length + ' lines are JSON objects with Zeek id.orig_h/uid fields.' };
    if (best && best === win) return { format: 'windows-auth-json', reason: win + ' of the first ' + head.length + ' lines carry EventID/TargetUserName.' };
    if (best && best === sys && sys >= Math.ceil(head.length / 2)) return { format: 'syslog-auth', reason: sys + ' of the first ' + head.length + ' lines match syslog framing.' };
    if (/,/.test(lines[0]) && !json) {
      const cells = (splitCSVRecord(lines[0]) || []).map(c => c.trim().toLowerCase().replace(/^\ufeff/, ''));
      const has = k => cells.some(c => CSV_COLUMNS[k].includes(c));
      if (has('time') && has('outcome') && (has('user') || has('src'))) return { format: 'auth-csv', reason: 'CSV header maps to time, outcome and account/source columns.' };
      if (/\.csv$/i.test(fileName)) return { format: null, reason: 'CSV header lacks time, outcome and account/source columns required for authentication analysis.' };
    }
    if (sys) return { format: 'syslog-auth', reason: 'Some lines match syslog framing (' + sys + ' of ' + head.length + '); non-matching lines will be rejected.' };
    return { format: null, reason: 'No supported format recognised in the first ' + head.length + ' lines.' };
  }

  /* ---------------------------------------------------------------- ingestion */
  function ranges(list) { const out = []; for (const n of list) { const last = out[out.length - 1]; if (last && last[1] === n - 1) last[1] = n; else out.push([n, n]); } return out; }
  function createSession() { return { fingerprints: new Map(), identities: new Map(), importsByFingerprint: new Map() }; }
  function removeImportFromSession(session, importId) {
    for (const [k, v] of session.fingerprints) if (v.importId === importId) session.fingerprints.delete(k);
    for (const [k, v] of session.identities) if (v.importId === importId) session.identities.delete(k);
  }
  function identitySignature(r) { return r.uid && r.uid.startsWith('csv-id:') ? [r.time, r.user, r.outcome, r.src].join('|') : [r.src, r.srcPort, r.dst, r.port].join('|'); }

  /* Line-oriented ingestor. Feed decoded text chunks; drain accepted records
     and annotations; read the receipt at any time. */
  function createIngestor({ importId, fileName, fileSize = null, format = 'auto', options = {}, session = createSession(), maxRecords = Infinity, received = Date.now(), origin = 'IMPORT' }) {
    const opts = defaultOptions(options);
    const ctx = { importId, fileName, format: null, opts, received, origin, setSeparator: ',', columnMapping: null };
    const receipt = {
      importId, fileName, fileSize, format: null, formatLabel: null, detection: null,
      options: { zoneOffsetMinutes: opts.zoneOffsetMinutes, syslogYear: opts.syslogYear, slashOrder: opts.slashOrder },
      status: 'running', startedAt: new Date(received).toISOString(), finishedAt: null,
      linesRead: 0, bytesRead: 0, metadataLines: 0, blankLines: 0, accepted: 0, rejected: 0,
      duplicates: { withinFile: 0, acrossImports: 0 }, timeQuality: {}, conflicts: { timestamp: 0, identity: 0 },
      rawTruncated: 0, replacementCharacters: 0, rejectReasons: {}, rejectSamples: [], rejectedLines: [], duplicateSamples: [], conflictSamples: [],
      columnMapping: null, limit: null, cancelled: null, error: null, assumptions: [], notes: []
    };
    let parser = null, buffer = '', lineNo = 0, detectBuffer = [], detectBytes = 0, stopped = false;
    const out = [], annotations = [], dups = [], rejectedLineNumbers = [];
    function chooseParser(fmt) {
      ctx.format = fmt; receipt.format = fmt; receipt.formatLabel = FORMATS[fmt];
      if (fmt === 'zeek-tsv') parser = createZeekTSV(ctx);
      else if (fmt === 'auth-csv') parser = createAuthCSV(ctx);
      else {
        const fn = { 'suricata-eve': parseEve, 'zeek-json': parseZeekJSON, 'syslog-auth': parseSyslog, 'windows-auth-json': parseWindowsAuth, 'text': parseText }[fmt];
        parser = { line: (text, line) => fn(text, line, ctx) };
      }
    }
    function reject(line, reason, text) {
      receipt.rejected++;
      const key = reason.replace(/"[^"]*"/g, '"…"').replace(/\d+/g, 'N').slice(0, 140);
      receipt.rejectReasons[key] = (receipt.rejectReasons[key] || 0) + 1;
      if (receipt.rejectSamples.length < 200) receipt.rejectSamples.push({ line, reason, excerpt: String(text ?? '').slice(0, 300) });
      rejectedLineNumbers.push(line);
    }
    function accept(result, text) {
      const r = result.record;
      if (receipt.accepted >= maxRecords) { stop('limit', r.line); return; }
      r.rawSha256 = sha256Text(text);
      r.rawBytes = utf8(text).length;
      const key = r.rawSha256 + (result.dedupScope ? '|' + result.dedupScope : '');
      const prior = session.fingerprints.get(key);
      if (prior) {
        if (prior.importId === importId) receipt.duplicates.withinFile++; else receipt.duplicates.acrossImports++;
        if (receipt.duplicateSamples.length < 50) receipt.duplicateSamples.push({ line: r.line, firstSeen: { id: prior.id, source: prior.source, line: prior.line } });
        dups.push({ id: prior.id, location: { importId, source: fileName, line: r.line } });
        return;
      }
      session.fingerprints.set(key, { id: r.id, importId, source: fileName, line: r.line });
      if (r.rawTruncated) receipt.rawTruncated++;
      if (text.includes('\ufffd')) { receipt.replacementCharacters++; note(r, 'Line contains U+FFFD replacement characters (invalid UTF-8 in the source or a literal replacement character).'); }
      if (r.uid) {
        const sig = identitySignature(r), seen = session.identities.get(r.uid);
        if (!seen) session.identities.set(r.uid, { sig, id: r.id, importId });
        else if (seen.sig !== sig) {
          const detail = r.uid.startsWith('csv-id:') ? 'Same event identifier recorded with different time, account, outcome or source.' : 'Same connection identifier recorded with a different address/port tuple.';
          const c = { type: 'identity', key: r.uid, otherId: seen.id, detail };
          (r.conflicts || (r.conflicts = [])).push(c);
          annotations.push({ id: seen.id, conflict: { type: 'identity', key: r.uid, otherId: r.id, detail } });
          receipt.conflicts.identity++;
          if (receipt.conflictSamples.length < 50) receipt.conflictSamples.push({ line: r.line, key: r.uid, otherId: seen.id, detail });
        }
      }
      if (r.conflicts?.some(c => c.type === 'timestamp')) {
        receipt.conflicts.timestamp++;
        if (receipt.conflictSamples.length < 50) receipt.conflictSamples.push({ line: r.line, key: 'timestamp', detail: r.conflicts.find(c => c.type === 'timestamp').detail });
      }
      receipt.timeQuality[r.timeQuality] = (receipt.timeQuality[r.timeQuality] || 0) + 1;
      receipt.accepted++;
      out.push(r);
    }
    function processLine(text, line) {
      receipt.linesRead++;
      if (!text.trim()) { receipt.blankLines++; return; }
      if (text.length > LINE_LIMIT) { reject(line, 'Line exceeds the 1 MiB per-record limit', text.slice(0, 300)); return; }
      if (/[\u0000-\u0008\u000e-\u001f]/.test(text) && (text.match(/[\u0000-\u0008\u000e-\u001f]/g) || []).length > Math.max(2, text.length * 0.05)) { reject(line, 'Binary or control characters; not a text log line', text.slice(0, 120).replace(/[\u0000-\u001f]/g, '·')); return; }
      let result;
      try { result = parser.line(text, line); } catch (e) { result = { reject: 'Parser error: ' + String(e.message).slice(0, 160) }; }
      handle(result, text, line);
    }
    function handle(result, text, line) {
      if (Array.isArray(result)) { for (const r of result) { if (stopped) return; handle(r, text, line); } return; }
      if (!result) return;
      const at = result.line ?? line, original = result.original ?? text;
      if (result.fatal) { receipt.status = 'failed'; receipt.error = result.fatal; stopped = true; return; }
      if (result.meta) { receipt.metadataLines++; return; }
      if (result.reject) { reject(at, result.reject, original); return; }
      if (result.record) accept(result, original);
    }
    function stop(kind, line) {
      if (stopped) return;
      stopped = true;
      if (kind === 'limit') { receipt.status = 'limit'; receipt.limit = { atLine: line, reason: 'Session retention limit reached; this line and the remainder of the file were not imported.' }; }
    }
    function runDetection(force) {
      const sample = detectBuffer.map(x => x[0]).join('\n');
      let det;
      if (format && format !== 'auto') det = { format, reason: 'Format selected by operator.' , manual: true };
      else det = detectFormat(sample, fileName);
      receipt.detection = { method: det.manual ? 'manual' : 'automatic', reason: det.reason };
      if (!det.format) { receipt.status = 'unrecognized'; receipt.error = det.reason; stopped = true; return false; }
      chooseParser(det.format);
      const pending = detectBuffer; detectBuffer = null;
      for (const [text, line] of pending) { if (stopped) break; processLine(text, line); }
      return true;
    }
    function pushLine(text, line) {
      if (stopped) return;
      if (detectBuffer) {
        detectBuffer.push([text, line]); detectBytes += text.length;
        if (detectBuffer.filter(x => x[0].trim()).length >= 40 || detectBytes > 65536) runDetection();
        return;
      }
      processLine(text, line);
    }
    return {
      receipt, ctx,
      push(chunk) {
        if (stopped) return;
        receipt.bytesRead += chunk.length;
        buffer += chunk;
        let start = 0;
        for (let i = 0; i < buffer.length; i++) {
          const c = buffer.charCodeAt(i);
          if (c === 10 || c === 13) {
            pushLine(buffer.slice(start, i), ++lineNo);
            if (c === 13 && buffer.charCodeAt(i + 1) === 10) i++;
            start = i + 1;
            if (stopped) { buffer = ''; return; }
          }
        }
        buffer = buffer.slice(start);
        if (buffer.length > LINE_LIMIT) { reject(lineNo + 1, 'Line exceeds the 1 MiB per-record limit', buffer.slice(0, 300)); buffer = ''; lineNo++; }
      },
      pushElements(elements) {
        ctx.containerNote = 'JSON array container: each element is stored as re-serialised JSON; the file SHA-256 covers the original bytes.';
        if (!receipt.notes.includes(ctx.containerNote)) receipt.notes.push(ctx.containerNote);
        if (detectBuffer) { const det = format && format !== 'auto' ? { format, reason: 'Format selected by operator.', manual: true } : detectFormat(JSON.stringify(elements.slice(0, 3)), fileName); receipt.detection = { method: det.manual ? 'manual' : 'automatic', reason: det.reason }; if (!det.format) { receipt.status = 'unrecognized'; receipt.error = det.reason; stopped = true; return; } chooseParser(det.format); detectBuffer = null; }
        for (const el of elements) {
          if (stopped) return;
          const text = JSON.stringify(el); lineNo++; receipt.linesRead++;
          let result;
          try { result = ctx.format === 'windows-auth-json' ? parseWindowsAuth(text, lineNo, ctx, el) : parser.line(text, lineNo); } catch (e) { result = { reject: 'Parser error: ' + String(e.message).slice(0, 160) }; }
          handle(result, text, lineNo);
        }
      },
      finish() {
        if (!stopped && buffer) { pushLine(buffer, ++lineNo); buffer = ''; }
        if (detectBuffer && !stopped) runDetection();
        if (!stopped && parser?.end) { const r = parser.end(); if (r) handle(r, '', lineNo); }
        if (receipt.status === 'running') receipt.status = 'complete';
        return this.seal();
      },
      cancel(line) { stopped = true; receipt.status = 'cancelled'; receipt.cancelled = { atLine: line ?? lineNo, bytesRead: receipt.bytesRead }; return this.seal(); },
      seal() {
        receipt.finishedAt = new Date().toISOString();
        receipt.columnMapping = ctx.columnMapping;
        receipt.rejectedLines = ranges(rejectedLineNumbers);
        const a = [];
        const tq = receipt.timeQuality;
        if (tq['assumed-zone']) a.push(tq['assumed-zone'] + ' timestamps had no UTC offset; UTC' + (opts.zoneOffsetMinutes ? (opts.zoneOffsetMinutes > 0 ? '+' : '') + opts.zoneOffsetMinutes / 60 : '') + ' was assumed.');
        if (tq['assumed-year']) a.push(tq['assumed-year'] + ' syslog timestamps had no year; ' + opts.syslogYear + ' and UTC' + (opts.zoneOffsetMinutes ? (opts.zoneOffsetMinutes > 0 ? '+' : '') + opts.zoneOffsetMinutes / 60 : '') + ' were assumed. Logs spanning a new year will be misdated.');
        if (tq['date-only']) a.push(tq['date-only'] + ' timestamps were dates without a time of day.');
        if (tq.ambiguous) a.push(tq.ambiguous + ' slash dates were ambiguous and left without a time; choose MDY or DMY to interpret them.');
        if (tq.implausible) a.push(tq.implausible + ' timestamps fell outside 1990 to import time + 2 days and are treated as unknown.');
        if (tq.missing || tq.unparseable) a.push(((tq.missing || 0) + (tq.unparseable || 0)) + ' records have no usable event time; they appear in the unknown-time bucket and are excluded from time-based rules.');
        receipt.assumptions = a;
        return receipt;
      },
      drain() { return { records: out.splice(0), annotations: annotations.splice(0), duplicates: dups.splice(0) }; },
      get stopped() { return stopped; },
      get lineNo() { return lineNo; }
    };
  }

  /* Convenience for tests and small inputs. */
  function ingestText(text, args = {}) {
    const ing = createIngestor(args);
    const trimmed = text.replace(/^\ufeff/, '').trimStart();
    if (trimmed.startsWith('[')) {
      let elements;
      try { elements = JSON.parse(trimmed); } catch (e) { ing.receipt.status = 'failed'; ing.receipt.error = 'JSON array could not be parsed: ' + e.message; ing.seal(); return { receipt: ing.receipt, records: [], annotations: [], duplicates: [] }; }
      ing.pushElements(Array.isArray(elements) ? elements : [elements]);
      ing.receipt.bytesRead = text.length;
    } else ing.push(text);
    const receipt = ing.finish();
    return { receipt, ...ing.drain() };
  }

  return {
    sha256Bytes, sha256Text, utf8, canonicalJSON,
    normalizeIP, ipScope, isInternal, isExternal, normalizePort, normalizeDomain,
    parseTimestamp, defaultOptions, QUALITY, USABLE, FORMATS, detectFormat,
    createIngestor, createSession, removeImportFromSession, ingestText, RAW_LIMIT, LINE_LIMIT, mapOutcome
  };
})();
if (typeof module !== 'undefined' && module.exports) module.exports = NVCore;
