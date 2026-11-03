const fs = require('node:fs');
const path = require('node:path');
const Core = require('../../src/investigation/core.js');
const Rules = require('../../src/investigation/rules.js');
const Cases = require('../../src/investigation/cases.js');

const FIXTURES = path.join(__dirname, '..', '..', 'fixtures');
const NOW = Date.UTC(2026, 10, 2, 12, 0, 0);

function ingestDir(dir, extra = {}) {
  const session = Core.createSession();
  const receipts = [], records = [], annotations = [], duplicates = [];
  let n = 0;
  for (const name of fs.readdirSync(path.join(FIXTURES, dir)).sort()) {
    const text = fs.readFileSync(path.join(FIXTURES, dir, name), 'utf8');
    const out = Core.ingestText(text, { importId: 'I' + (++n), fileName: name, session, options: { now: NOW }, ...extra });
    receipts.push(out.receipt); records.push(...out.records); annotations.push(...out.annotations); duplicates.push(...out.duplicates);
  }
  return { receipts, records, annotations, duplicates, session };
}
function ingest(text, args = {}) { return Core.ingestText(text, { importId: 'T', fileName: 'test', options: { now: NOW }, ...args }); }

module.exports = { Core, Rules, Cases, FIXTURES, NOW, ingestDir, ingest, fs, path };
