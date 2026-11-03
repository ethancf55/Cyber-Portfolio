#!/usr/bin/env node
/* Assemble the self-contained NEXUS VORTEX HTML from the public-edition
   baseline plus the incident-reconstruction sources. No network, no minify. */
import { readFileSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const src = (...p) => join(root, 'src', ...p);
const read = p => readFileSync(p, 'utf8');
const stripExport = code => code.replace(/\nif \(typeof module !== 'undefined' && module\.exports\) module\.exports = \w+;\n?/, '\n');

function must(html, from, to, label) {
  const n = html.split(from).length - 1;
  if (n !== 1) throw new Error(label + ': expected 1 occurrence, found ' + n);
  return html.replace(from, to);
}

const syncEvidence = `
  function evidenceId(key){let h=2166136261;for(let i=0;i<key.length;i++){h^=key.charCodeAt(i);h=Math.imul(h,16777619);}return 'ev-'+(h>>>0).toString(16);}
  function syncEvidence(spec){
    const keep=new Set((spec.nodes||[]).map(a=>evidenceId(a.key)));
    for(let i=nodes.length-1;i>=0;i--)if(nodes[i].evidence&&!keep.has(nodes[i].id))nodes.splice(i,1);
    for(let i=edges.length-1;i>=0;i--)if(edges[i].evidence)edges.splice(i,1);
    nodes.forEach(n=>{if(n.adjacency)n.adjacency=n.adjacency.filter(e=>!e.evidence);});
    const byKey=new Map();
    for(const a of spec.nodes||[]){
      const id=evidenceId(a.key);let n=nodes.find(x=>x.id===id);
      if(!n){n=makeNode(nodes.length,a.pos,'outer','endpoint');Object.assign(n,{id,evidence:true,local:true,sensor:'evidence',assetKey:a.key,name:String(a.label).slice(0,80),ip:'From imported evidence',tech:[],riskHistory:[],packets:'Not captured',latency:'Not measured',group:'imported evidence',adjacency:[],openPorts:[]});nodes.push(n);}
      n.pos=a.pos;n.name=String(a.label).slice(0,80);n.evidenceKind=a.kind;n.assetKey=a.key;n.risk=a.weight;n.status=a.focus?'suspicious':'secure';n.confidence=0;n.dimmed=!!a.dim;n.focused=!!a.focus;n.localCount=a.count;n.anomaly=a.count+' records in the investigation window';n.localEvent={title:a.count+' records in window',detail:String(a.kind||'').toUpperCase(),count:a.count};byKey.set(a.key,n);
    }
    for(const e of spec.edges||[]){
      const a=byKey.get(e.a),b=byKey.get(e.b);if(!a||!b)continue;const edge=addEdge(a,b);
      Object.assign(edge,{evidence:true,observed:true,local:true,evidenceKind:e.kind,inferred:e.kind==='inferred',evidenceKey:e.key,focus:!!e.focus,dimmed:!!e.dim,selectedEdge:!!e.selected,count:e.count,hostile:false});
      if(!a.adjacency.includes(edge))a.adjacency.push(edge);if(!b.adjacency.includes(edge))b.adjacency.push(edge);
    }
    if(get(selectedId)?.evidence&&!keep.has(selectedId))selectedId=nodes.find(n=>n.local&&!n.evidence)?.id||nodes[0].id;
    notify();
  }
`;

let html = read(src('public-edition.html'));

html = must(html,
  '<button class="navbtn" data-route="defense" data-tip="Sentinel Array / Local Defense" aria-label="Sentinel Array"><svg class="icon"><use href="#i-shield"/></svg><span class="navbtn__code">10</span></button>',
  '<button class="navbtn" data-route="defense" data-tip="Sentinel Array / Local Defense" aria-label="Sentinel Array"><svg class="icon"><use href="#i-shield"/></svg><span class="navbtn__code">10</span></button><button class="navbtn" data-route="investigate" data-tip="Incident Reconstruction" aria-label="Incident Reconstruction"><svg class="icon"><use href="#i-search"/></svg><span class="navbtn__code">12</span></button>',
  'rail button');

html = must(html,
  '<button class="mobile-nav__btn" data-route="operations"><svg class="icon"><use href="#i-database"/></svg><span>OPS</span></button>',
  '<button class="mobile-nav__btn" data-route="investigate"><svg class="icon"><use href="#i-search"/></svg><span>IR</span></button><button class="mobile-nav__btn" data-route="operations"><svg class="icon"><use href="#i-database"/></svg><span>OPS</span></button>',
  'mobile nav');

html = must(html, '<footer class="app-footer">', read(src('investigation', 'workspace.html')) + '\n      <footer class="app-footer">', 'workspace markup');
html = must(html, '<span>NEXUS VORTEX 10.1</span>', '<span>NEXUS VORTEX 11.1</span>', 'footer version');
html = must(html, '<span>NV / 10.1</span>', '<span>NV / 11.1</span>', 'provenance version');
html = must(html, '<span class="ok">● SECURE</span><span class="barcode"></span><span>NV-OS 9.0</span>', '<span class="ok">● LOCAL</span><span class="barcode"></span><span>NV 11.1</span>', 'rail status');
html = must(html,
  '<p>NEXUS VORTEX is a closed simulation environment. Every signal, node, process, and exploit chain is synthetic. Operator records are stored only in this browser\'s local sandbox.</p>',
  '<p>Incident Reconstruction, the Evidence Lab, hashing and saved cases run on imported evidence in this browser. The Command Deck theater, detection-feed scoring, memory view, exploit chains and C2 chamber are labelled simulations. Nothing is uploaded.</p>',
  'help note');

html = must(html, '</head>', '<style>\n' + read(src('investigation', 'workspace.css')) + '\n</style>\n</head>', 'css');

html = must(html, "  { id: 'operations', idx: '10', name: 'Security Operations' }\n];",
  "  { id: 'operations', idx: '10', name: 'Security Operations' },\n  { id: 'investigate', idx: '11', name: 'Incident Reconstruction' }\n];", 'routes');

html = must(html,
  'if (lattice) lattice.textContent = `${(97.4 + Math.sin(Date.now() / 9000) * 1.1).toFixed(1)}%`;',
  "if (lattice && !MeshModel.evidenceOnly) lattice.textContent = `${(97.4 + Math.sin(Date.now() / 9000) * 1.1).toFixed(1)}%`;",
  'operator chrome');

html = must(html, '  function topNodes(count = 10)', syncEvidence + '  function topNodes(count = 10)', 'syncEvidence');
html = must(html, 'nodes, edges, flows, events, path, pathPairs, R, syncObserved,',
  'nodes, edges, flows, events, path, pathPairs, R, syncObserved, syncEvidence,', 'mesh export');

html = must(html,
  "if (MeshModel.evidenceOnly && !n.local) st={color:'#366575',rgb:'54,101,117'};",
  `if (n.evidence) { const palette = { internal: ['0,240,255','#00f0ff'], external: ['157,123,255','#9d7bff'], domain: ['203,255,92','#cbff5c'], account: ['255,182,72','#ffb648'], host: ['105,255,176','#69ffb0'] }; const pair = palette[n.evidenceKind] || palette.external; st = n.dimmed ? { color:'#2c4a55', rgb:'44,74,85' } : { color: pair[1], rgb: pair[0] }; }
      if (MeshModel.evidenceOnly && !n.local) st={color:'#366575',rgb:'54,101,117'};`,
  'node colours');

html = must(html, 'if (n.local) {', 'if (n.local && !n.evidence) {', 'sensor labels');
html = must(html,
  '    // selected node label in-scene\n    if (selected) {',
  '    // selected node label in-scene\n    if (selected && !(MeshModel.evidenceOnly && !selected.local && !selected.evidence)) {',
  'sim label');

html = must(html,
  'if (e.local) { alpha = .55; color = \'105,255,176\'; width = 1.4; }',
  `if (e.local && !e.evidence) { alpha = .55; color = '105,255,176'; width = 1.4; }
      if (e.evidence) { const palette = { comm:'0,240,255', 'dns-query':'203,255,92', 'dns-answer':'203,255,92', auth:'255,182,72', 'auth-target':'255,182,72', inferred:'255,43,214' }; color = palette[e.evidenceKind] || '0,240,255'; alpha = e.dimmed ? .07 : (e.focus || e.selectedEdge) ? .9 : .4; width = e.focus ? 1.8 : 1; }
      ctx.setLineDash(e.inferred ? [6, 5] : []);`,
  'edge colours');

html = must(html,
  'if (incident || inTrace) {\n        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.quadraticCurveTo(cxp, cyp, e.local ? lerp(a.x,b.x,REDUCED ? 1 : clamp((ts-(e.localPulse||0))/800,0,1)) : b.x, e.local ? lerp(a.y,b.y,REDUCED ? 1 : clamp((ts-(e.localPulse||0))/800,0,1)) : b.y);\n        ctx.strokeStyle = `rgba(${color},${alpha * .22})`; ctx.lineWidth = width * 4; ctx.stroke();\n      }',
  `if ((incident || inTrace) && !e.inferred) {
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.quadraticCurveTo(cxp, cyp, b.x, b.y);
        ctx.strokeStyle = \`rgba(\${color},\${alpha * .22})\`; ctx.lineWidth = width * 4; ctx.stroke();
      }
      ctx.setLineDash([]);`,
  'edge glow');

html = must(html,
  'if (!e || (MeshModel.evidenceOnly && !e.observed)) continue;',
  'if (!e || e.inferred || (MeshModel.evidenceOnly && !e.observed)) continue;',
  'packets');

html = must(html,
  "${node.observedAsset?(node.localCount?'SOURCE HIGH':'OBSERVED'):st.label}",
  "${node.evidence?(String(node.evidenceKind||'EVIDENCE').toUpperCase()+' / '+node.localCount):node.observedAsset?(node.localCount?'SOURCE HIGH':'OBSERVED'):st.label}",
  'tooltip');

html = must(html,
  "${n.observedAsset?'EVIDENCE // '+(n.localCount?'SOURCE HIGH':'OBSERVED'):n.local?'LOCAL SENSOR':MeshZones[n.zone].label+' // '+st.label}",
  "${n.evidence?'EVIDENCE // '+String(n.evidenceKind||'').toUpperCase()+' // '+n.localCount:n.observedAsset?'EVIDENCE // '+(n.localCount?'SOURCE HIGH':'OBSERVED'):n.local?'LOCAL SENSOR':MeshZones[n.zone].label+' // '+st.label}",
  'node index');

if (!html.includes('host.innerHTML = NodeIntel.html(node);')) throw new Error('renderIntel anchor missing');
html = html.replace(
  'host.innerHTML = NodeIntel.html(node);\n    $$(\'#view-mesh [data-node-action]\').forEach(button => { button.disabled = !!node?.local; button.title = node?.local ? \'Use Sentinel Array controls for local sensors\' : \'\'; });\n    const badge = $(\'#meshIntelBadge\'); if (badge) {\n      const st = node ? MeshStatus[node.status] : null;\n      badge.textContent = node?.local ? (node.risk ? \'REVIEW REQUIRED\' : node.localEvent ? \'OBSERVED\' : \'IDLE\') : node ? st.label : \'NO LOCK\';',
  `const evidencePanel = MeshModel.evidenceOnly && typeof SecurityFabric !== 'undefined' && SecurityFabric.intelHTML?.();
    host.innerHTML = evidencePanel || NodeIntel.html(node);
    $$('#view-mesh [data-node-action]').forEach(button => { button.disabled = !!(node?.local || node?.evidence || evidencePanel); button.title = (node?.evidence || evidencePanel) ? 'Evidence nodes are inspected here; simulated containment applies to training nodes only' : node?.local ? 'Use Sentinel Array controls for local sensors' : ''; });
    const badge = $('#meshIntelBadge'); if (badge) {
      const st = node ? MeshStatus[node.status] : null;
      badge.textContent = evidencePanel ? 'EVIDENCE' : node?.local ? (node.risk ? 'REVIEW REQUIRED' : node.localEvent ? 'OBSERVED' : 'IDLE') : node ? st.label : 'NO LOCK';`
);

html = must(html,
  "const feed = $('#meshFeed'); if (feed) feed.innerHTML = MeshModel.evidenceOnly ? SecurityFabric.observations.slice(-7).reverse().map(r=>`<div class=\"line\"><time>${esc((r.time||r.received||'').slice(11,19))}</time><em>${esc(r.origin)}</em><span>${esc(r.message.slice(0,180))}</span></div>`).join('')||'<p class=\"fabric-empty\">No source observations yet.</p>' : MeshFragments.feed();",
  "const feed = $('#meshFeed'); if (feed) feed.innerHTML = MeshModel.evidenceOnly ? SecurityFabric.observations.slice(-7).reverse().map(r=>`<div class=\"line\"><time>${esc(UTC.clock(r.time ?? r.received))}</time><em>${esc(r.kind || r.origin)}</em><span>${esc(String(r.message || '').slice(0,180))}</span></div>`).join('')||'<p class=\"fabric-empty\">No source observations in this window.</p>' : MeshFragments.feed();",
  'mesh feed');

html = must(html,
  'const el = $(\'#timelineElapsed\'); if (el) { const sec = Math.floor((performance.now() - mountedAt) / 1000); el.textContent = `ELAPSED ${pad2(Math.floor(sec / 60))}:${pad2(sec % 60)}`; }\n      const upt = $(\'#cmdUptime\'); if (upt) { const sec = Math.floor((performance.now() - mountedAt) / 1000) + 47 * 3600 + 12 * 60; upt.textContent = `UPLINK ${pad2(Math.floor(sec / 3600))}:${pad2(Math.floor(sec / 60) % 60)}:${pad2(sec % 60)}`; }',
  'const el = $(\'#timelineElapsed\'); if (el && !MeshModel.evidenceOnly) { const sec = Math.floor((performance.now() - mountedAt) / 1000); el.textContent = `ELAPSED ${pad2(Math.floor(sec / 60))}:${pad2(sec % 60)}`; }\n      const upt = $(\'#cmdUptime\'); if (upt && !MeshModel.evidenceOnly) { const sec = Math.floor((performance.now() - mountedAt) / 1000) + 47 * 3600 + 12 * 60; upt.textContent = `UPLINK ${pad2(Math.floor(sec / 3600))}:${pad2(Math.floor(sec / 60) % 60)}:${pad2(sec % 60)}`; }',
  'fake clocks');

html = must(html, 'return {mount(){render();renderTools();', 'return {get companion(){return !!config},mount(){render();renderTools();', 'companion flag');

html = must(html,
  "const routeIcons = { command: 'i-command', mesh: 'i-mesh', feed: 'i-feed', topology: 'i-topology', forensics: 'i-memory', exploit: 'i-chain', behavior: 'i-behavior', signals: 'i-c2', lab: 'i-database', defense: 'i-shield', operations: 'i-database' };",
  "const routeIcons = { command: 'i-command', mesh: 'i-mesh', feed: 'i-feed', topology: 'i-topology', forensics: 'i-memory', exploit: 'i-chain', behavior: 'i-behavior', signals: 'i-c2', lab: 'i-database', defense: 'i-shield', operations: 'i-database', investigate: 'i-search' };",
  'palette icons');

html = must(html,
  "operations: Operations, security: SecurityFabric, version: '11.0',",
  "operations: Operations, security: SecurityFabric, investigation: { Evidence, Investigation, Ingest, CaseStore, Workspace }, version: '11.1',",
  'export');

html = must(html,
  'forensics: ForensicsView, exploit: ExploitView, behavior: BehaviorView, signals: SignalsView, lab: EvidenceLab, defense: Defense, operations: Operations',
  'forensics: ForensicsView, exploit: ExploitView, behavior: BehaviorView, signals: SignalsView, lab: EvidenceLab, defense: Defense, operations: Operations, investigate: Workspace',
  'modules');

const fixtures = {};
for (const dir of ['benign', 'suspicious', 'malformed', 'timestamps', 'hostile']) {
  const base = join(root, 'fixtures', dir);
  fixtures[dir] = readdirSync(base).filter(n => !n.startsWith('.')).sort().map(name => ({ name: dir + '/' + name, text: read(join(base, name)) }));
}

const worker = ['core.js', 'rules.js', 'engine.js'].map(n => stripExport(read(src('investigation', n)))).join('\n') + `
const engine = NVIngestEngine.create(m => self.postMessage(m));
self.onmessage = e => { const job = engine.handle(e.data); if (job && typeof job.then === 'function') job.catch(err => self.postMessage({ type:'done', jobId:e.data.jobId, importId:e.data.importId, receipt:{ status:'failed', error:String(err && err.message || err), fileName:e.data.fileName, accepted:0, rejected:0, duplicates:{withinFile:0,acrossImports:0}, assumptions:[], notes:[] } })); };
`;
if (worker.includes('</script>')) throw new Error('worker source contains a script terminator');

const pageModules = ['core.js', 'rules.js', 'cases.js', 'engine.js', 'synthetic.js'].map(n => stripExport(read(src('investigation', n)))).join('\n')
  + '\nconst NV_FIXTURES = ' + JSON.stringify(fixtures).replace(/</g, '\\u003c') + ';\n'
  + read(src('investigation', 'workspace.js')) + '\n';
if (pageModules.includes('</script>')) throw new Error('page modules contain a script terminator');

const start = html.indexOf('/* NEXUS_SECURITY_FABRIC_START */');
const end = html.indexOf('/* NEXUS_SECURITY_FABRIC_END */');
if (start < 0 || end < start) throw new Error('fabric markers missing');
html = html.slice(0, start) + pageModules + html.slice(end + '/* NEXUS_SECURITY_FABRIC_END */'.length);

const workerTag = '<script type="text/plain" id="nvIngestWorker">' + worker + '</script>\n';
html = must(html, '<script>\n(() => {\n\'use strict\';', workerTag + '<script>\n(() => {\n\'use strict\';', 'worker tag');

const publicHtml = html;
const localHtml = html.replace(
  '<strong>NEXUS VORTEX / PUBLIC WEB EDITION</strong><p>Explore the Neural Threat Mesh, training simulations, file hashing, and imported evidence analysis. Selected files are processed in this browser; this edition has no server-side log upload or account credentials.</p>',
  '<strong>NEXUS VORTEX / LOCAL EDITION</strong><p>Same browser workspace as the public edition, plus the local companion for live logs, scoped scans and account connectors. Credentials stay in the companion process. Evidence is still not uploaded.</p>'
).replace(/<script>\n\(\(\) => \{\n  const message = 'LOCAL COMPANION REQUIRED[\s\S]*?<\/script>\n/, '');

for (const [dir, body] of [['public', publicHtml], ['local', localHtml]]) {
  const out = join(root, 'dist', dir);
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'index.html'), body);
  console.log(dir, (body.length / 1048576).toFixed(2) + ' MiB');
}
