/* ThreatLens front-end. All feed-derived strings pass through esc() — feed content is untrusted. */
(() => {
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const safeUrl = u => /^https?:\/\//i.test(u) ? esc(u) : '#';
const fmt = n => (n ?? 0).toLocaleString();
const ago = iso => { const d = (Date.now() - new Date(iso)) / 864e5; return d < 1 ? 'today' : d < 2 ? 'yesterday' : Math.floor(d) + 'd ago'; };
const defang = (v, t) => t === 'url' ? v.replace(/^http/i, 'hxxp').replace(/\./g, '[.]') : (t === 'domain' || t === 'ipv4') ? v.replace(/\./g, '[.]') : t === 'email' ? v.replace('@', '[@]').replace(/\./g, '[.]') : v;
const FLAGS = { RU: '🇷🇺', CN: '🇨🇳', KP: '🇰🇵', IR: '🇮🇷', US: '🇺🇸', IN: '🇮🇳', PK: '🇵🇰', VN: '🇻🇳', BY: '🇧🇾', KR: '🇰🇷', SD: '🇸🇩', Intl: '🌐', '??': '❔' };
const ATTACK = { T1566: 'Phishing', T1059: 'Command & Scripting', T1190: 'Exploit Public-Facing App', T1078: 'Valid Accounts', T1105: 'Ingress Tool Transfer', T1027: 'Obfuscated Files', T1071: 'App Layer Protocol', T1055: 'Process Injection', T1053: 'Scheduled Task', T1547: 'Boot/Logon Autostart', T1036: 'Masquerading', T1070: 'Indicator Removal', T1082: 'System Info Discovery', T1083: 'File & Dir Discovery', T1003: 'OS Credential Dumping', T1021: 'Remote Services', T1486: 'Data Encrypted for Impact', T1041: 'Exfil Over C2', T1204: 'User Execution', T1218: 'System Binary Proxy Exec', T1562: 'Impair Defenses', T1112: 'Modify Registry', T1140: 'Deobfuscate/Decode', T1056: 'Input Capture', T1057: 'Process Discovery', T1012: 'Query Registry', T1018: 'Remote System Discovery', T1033: 'System Owner Discovery', T1046: 'Network Service Discovery', T1074: 'Data Staged', T1090: 'Proxy', T1095: 'Non-App Layer Protocol', T1102: 'Web Service', T1133: 'External Remote Services', T1189: 'Drive-by Compromise', T1195: 'Supply Chain Compromise', T1203: 'Exploitation for Client Exec', T1219: 'Remote Access Software', T1485: 'Data Destruction', T1490: 'Inhibit System Recovery', T1496: 'Resource Hijacking', T1505: 'Server Software Component', T1543: 'Create/Modify System Process', T1546: 'Event Triggered Execution', T1553: 'Subvert Trust Controls', T1560: 'Archive Collected Data', T1567: 'Exfil Over Web Service', T1568: 'Dynamic Resolution', T1573: 'Encrypted Channel', T1574: 'Hijack Execution Flow', T1587: 'Develop Capabilities', T1588: 'Obtain Capabilities', T1589: 'Gather Victim Identity', T1595: 'Active Scanning', T1598: 'Phishing for Information', T1621: 'MFA Request Generation' };
const COUNTRY = { RU: 'Russia', CN: 'China', KP: 'North Korea', IR: 'Iran', US: 'United States', IN: 'India', PK: 'Pakistan', VN: 'Vietnam', BY: 'Belarus', KR: 'South Korea', SD: 'Sudan', Intl: 'eCrime / Intl', '??': 'Unattributed' };

let META, REPORTS = [], GROUPS = [], KEV, IOCS = [], repById = new Map();

async function j(u) { const r = await fetch(u, { cache: 'no-cache' }); if (!r.ok) throw new Error(u); return r.json(); }
async function init() {
  try {
    [META, GROUPS, KEV] = await Promise.all([j('data/meta.json'), j('data/groups.json'), j('data/kev.json').catch(() => null)]);
    REPORTS = (await j('data/reports.json')).reports; repById = new Map(REPORTS.map(r => [r.id, r]));
    IOCS = await j('iocs/all.json').catch(() => []);
  } catch (e) {
    $('#overview').innerHTML = '<div class="empty">No data yet. Run <code>node collector/collect.mjs</code> (or trigger a Netlify build) to collect the first batch.</div>'; return;
  }
  $('#updated').textContent = 'updated ' + new Date(META.updated).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  const age = (Date.now() - new Date(META.updated)) / 36e5; if (age > 48) { $('#live').textContent = 'STALE'; $('#live').style.color = 'var(--warn)'; $('#live').style.borderColor = 'var(--warn)'; }
  buildOverview(); buildReports(); buildGroups(); buildIocs(); buildAttack(); buildKev(); buildSources(); route();
}

/* ---------- tabs ---------- */
function show(tab) {
  if (!$('#' + tab)) tab = 'overview';
  $$('.tab').forEach(t => t.classList.toggle('on', t.id === tab)); $$('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === tab));
  if (location.hash !== '#' + tab) history.replaceState(null, '', '#' + tab); scrollTo({ top: 0 });
}
const route = () => show(location.hash.slice(1) || 'overview');
$('#tabs').onclick = e => { const b = e.target.closest('button'); if (b) show(b.dataset.tab); };
addEventListener('hashchange', route);

/* ---------- chart helpers ---------- */
function hbars(el, rows, cb, color) {
  const max = Math.max(1, ...rows.map(r => r[1]));
  $(el).innerHTML = rows.map((r, i) => `<div class="hbar" data-i="${i}"><span class="lbl" title="${esc(r[0])}">${r[2] || ''}${esc(r[0])}</span><span class="track"><span class="fill" style="display:block;width:${(r[1] / max * 100).toFixed(1)}%;${color ? 'background:' + color : ''}"></span></span><span class="n">${fmt(r[1])}</span></div>`).join('') || '<div class="muted">No data</div>';
  if (cb) $(el).onclick = e => { const h = e.target.closest('.hbar'); if (h) cb(rows[+h.dataset.i]); };
}
function dailyChart() {
  const d = Object.entries(META.daily), W = 640, H = 170, P = 22, bw = (W - P) / d.length;
  const mr = Math.max(1, ...d.map(x => x[1].reports)), mi = Math.max(1, ...d.map(x => x[1].iocs));
  const bars = d.map(([k, v], i) => { const h = v.reports / mr * (H - 30), x = P + i * bw; return `<rect x="${x + 1}" y="${H - 18 - h}" width="${bw - 2}" height="${Math.max(h, 1)}" rx="2"><title>${k}: ${v.reports} reports, ${v.iocs} IoCs</title></rect>`; }).join('');
  const line = d.map(([, v], i) => `${i ? 'L' : 'M'}${(P + i * bw + bw / 2).toFixed(1)},${(H - 18 - v.iocs / mi * (H - 30)).toFixed(1)}`).join('');
  $('#chartDaily').innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="100%"><g class="bars">${bars}</g><path d="${line}" fill="none" stroke="#ffb020" stroke-width="1.6" opacity=".9"/><text x="0" y="12">${mr}</text><text x="${P}" y="${H - 3}">${d[0][0].slice(5)}</text><text x="${W - 30}" y="${H - 3}">${d[d.length - 1][0].slice(5)}</text><text x="${W - 150}" y="12" style="fill:#ffb020">━ IoCs/day (max ${mi})</text><text x="${W - 300}" y="12" style="fill:#3da5ff">▮ reports/day</text></svg>`;
}

/* ---------- overview ---------- */
function buildOverview() {
  const t = META.totals;
  $('#kpis').innerHTML = [['Reports tracked', t.reports, `+${t.reports7d} this week`, '--acc2'], ['Threat actors', t.groups, 'attributed', '--vio'], ['Unique IoCs', t.iocs, `+${fmt(t.iocsThisRun)} last run`, '--warn'], ['CVEs referenced', t.cves, KEV ? fmt(KEV.total) + ' in CISA KEV' : '', '--bad'], ['Live sources', `${t.sourcesOk}/${t.sources}`, 'feeds healthy', '--acc']]
    .map(([l, v, s, c]) => `<div class="kpi" style="--c:var(${c})"><span>${l}</span><b>${typeof v === 'number' ? fmt(v) : esc(v)}</b><small>${esc(s)}</small></div>`).join('');
  dailyChart();
  hbars('#chartGroups', GROUPS.slice(0, 10).map(g => [g.name, g.reportCount, (FLAGS[g.country] || '') + ' ']), r => openGroup(r[0]));
  hbars('#chartCountry', Object.entries(META.countries).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([c, n]) => [COUNTRY[c] || c, n, (FLAGS[c] || '') + ' ']), null, 'linear-gradient(90deg,#a78bfa,#3da5ff)');
  hbars('#chartIoc', Object.entries(META.iocTypes).sort((a, b) => b[1] - a[1]).map(([k, n]) => [k, n]), r => { $('#it').value = r[0]; show('iocs'); renderIocs(true); }, 'linear-gradient(90deg,#ffb020,#ff4d6d)');
  $('#chartTags').innerHTML = Object.entries(META.tags).sort((a, b) => b[1] - a[1]).slice(0, 16).map(([k, n]) => `<span data-tag="${esc(k)}" style="font-size:${11 + Math.min(8, n / 12)}px">${esc(k)} <b>${n}</b></span>`).join('');
  $('#chartTags').onclick = e => { const s = e.target.closest('span'); if (s) { $('#rtag').value = s.dataset.tag; $('#rrange').value = '9999'; show('reports'); renderReports(true); } };
  $('#topReports').innerHTML = [...REPORTS].filter(r => Date.now() - new Date(r.published) < 30 * 864e5).sort((a, b) => b.score - a.score).slice(0, 7).map(repHtml).join('');
  $('#topCves').innerHTML = META.topCves.slice(0, 14).map(c => `<div class="hbar" style="grid-template-columns:140px 1fr 30px"><a class="lbl" target="_blank" rel="noopener" href="https://nvd.nist.gov/vuln/detail/${esc(c.cve)}" style="font-family:var(--mono)">${esc(c.cve)}</a><span class="track"><span class="fill" style="display:block;width:${c.n / META.topCves[0].n * 100}%;background:linear-gradient(90deg,#ff4d6d,#ffb020)"></span></span><span class="n">${c.n}</span></div>${c.kev ? '' : ''}`).join('');
  $('#q').oninput = lookup;
}
function lookup() {
  const q = $('#q').value.trim().toLowerCase().replace(/\[\.\]/g, '.'); const out = $('#qres'); if (q.length < 3) { out.innerHTML = ''; return; }
  const hits = [];
  GROUPS.filter(g => (g.name + ' ' + g.aliases.join(' ')).toLowerCase().includes(q)).slice(0, 4).forEach(g => hits.push(`<div class="hit" data-g="${esc(g.name)}">${FLAGS[g.country] || ''} <b>${esc(g.name)}</b> <span class="muted">${g.reportCount} reports</span></div>`));
  IOCS.filter(i => i.v.includes(q)).slice(0, 5).forEach(i => hits.push(`<div class="hit" data-i="${esc(i.v)}"><span class="ty ${esc(i.t)}">${esc(i.t)}</span> <code>${esc(defang(i.v, i.t)).slice(0, 60)}</code> <span class="muted">${esc(i.g.slice(0, 2).join(', '))}</span></div>`));
  if (/^cve-/.test(q)) { const n = REPORTS.filter(r => r.cves.some(c => c.toLowerCase() === q)).length; hits.push(`<div class="hit" data-r="${esc(q)}">🔥 <b>${esc(q.toUpperCase())}</b> <span class="muted">mentioned in ${n} reports</span></div>`); }
  out.innerHTML = hits.join('') || '<div class="muted" style="padding:6px">No match</div>';
}
$('#qres').onclick = e => { const h = e.target.closest('.hit'); if (!h) return; if (h.dataset.g) openGroup(h.dataset.g); else if (h.dataset.i) { $('#iq').value = h.dataset.i; show('iocs'); renderIocs(true); } else { $('#rq').value = h.dataset.r; $('#rrange').value = '9999'; show('reports'); renderReports(true); } };

/* ---------- reports ---------- */
function scoreColor(s) { return s >= 70 ? 'var(--bad)' : s >= 40 ? 'var(--warn)' : 'var(--acc2)'; }
function repHtml(r) {
  const ic = Object.entries(r.iocCounts || {}).map(([k, v]) => `${v} ${k}`).join(' · ');
  return `<article class="rep" data-id="${esc(r.id)}"><div class="score" style="--p:${r.score};--c:${scoreColor(r.score)}" data-s="${r.score}" title="Threat score"></div><div>
  <h4><a href="${safeUrl(r.url)}" target="_blank" rel="noopener noreferrer">${esc(r.title)}</a></h4>
  <div class="meta"><span>${esc(r.source)}</span><span>${esc(r.published.slice(0, 10))} · ${ago(r.published)}</span>${r.sourceType === 'gov' ? '<span class="flag">GOV</span>' : ''}${r.deep ? '' : '<span title="Only the feed teaser was analysed">teaser</span>'}</div>
  ${r.summary ? `<p class="sum">${esc(r.summary.slice(0, 230))}…</p>` : ''}
  <div class="chips">${r.groups.map(g => `<span class="chip g" data-g="${esc(g.name)}">${FLAGS[g.country] || ''} ${esc(g.name)}</span>`).join('')}${r.iocTotal ? `<span class="chip i" data-ioc="${esc(r.id)}" title="${esc(ic)}">⚑ ${r.iocTotal} IoCs</span>` : ''}${r.cves.slice(0, 4).map(c => `<span class="chip c">${esc(c)}</span>`).join('')}${r.cves.length > 4 ? `<span class="chip">+${r.cves.length - 4} CVEs</span>` : ''}${r.tags.slice(0, 4).map(t => `<span class="chip t" data-tag="${esc(t)}">#${esc(t)}</span>`).join('')}</div></div></article>`;
}
let rShown = 0, rFiltered = [];
function buildReports() {
  const src = [...new Set(REPORTS.map(r => r.source))].sort(); $('#rsrc').innerHTML += src.map(s => `<option>${esc(s)}</option>`).join('');
  $('#rtag').innerHTML += Object.keys(META.tags).sort().map(s => `<option>${esc(s)}</option>`).join('');
  ['#rq', '#rsrc', '#rtype', '#rtag', '#rrange', '#rapt', '#rioc'].forEach(s => $(s).addEventListener('input', () => renderReports(true)));
  $('#rmore').onclick = () => renderReports(false); $('#rlist').onclick = repClick; $('#topReports').onclick = repClick;
  renderReports(true);
}
function repClick(e) {
  const g = e.target.closest('[data-g]'); if (g) return openGroup(g.dataset.g);
  const t = e.target.closest('[data-tag]'); if (t) { $('#rtag').value = t.dataset.tag; $('#rrange').value = '9999'; show('reports'); return renderReports(true); }
  const i = e.target.closest('[data-ioc]'); if (i) openReportIocs(i.dataset.ioc);
}
function renderReports(reset) {
  if (reset) {
    const q = $('#rq').value.toLowerCase(), cut = Date.now() - +$('#rrange').value * 864e5;
    rFiltered = REPORTS.filter(r => new Date(r.published) >= cut && (!$('#rsrc').value || r.source === $('#rsrc').value) && (!$('#rtype').value || r.sourceType === $('#rtype').value) && (!$('#rtag').value || r.tags.includes($('#rtag').value)) && (!$('#rapt').checked || r.groups.length) && (!$('#rioc').checked || r.iocTotal) &&
      (!q || (r.title + ' ' + r.summary + ' ' + r.groups.map(g => g.name).join(' ') + ' ' + r.cves.join(' ')).toLowerCase().includes(q)));
    rShown = 0; $('#rlist').innerHTML = ''; $('#rcount').textContent = `${fmt(rFiltered.length)} reports`;
  }
  $('#rlist').insertAdjacentHTML('beforeend', rFiltered.slice(rShown, rShown + 25).map(repHtml).join('')); rShown += 25;
  $('#rmore').style.display = rShown < rFiltered.length ? '' : 'none';
  if (!rFiltered.length) $('#rlist').innerHTML = '<div class="empty">No reports match.</div>';
}

/* ---------- groups ---------- */
function buildGroups() {
  $('#gc').innerHTML += Object.keys(META.countries).sort().map(c => `<option value="${esc(c)}">${esc(COUNTRY[c] || c)}</option>`).join('');
  ['#gq', '#gc', '#gk'].forEach(s => $(s).addEventListener('input', renderGroups)); $('#glist').onclick = e => { const c = e.target.closest('.gc'); if (c) openGroup(c.dataset.n); }; renderGroups();
}
function renderGroups() {
  const q = $('#gq').value.toLowerCase(), c = $('#gc').value, k = $('#gk').checked;
  const list = GROUPS.filter(g => (!c || g.country === c) && (!k || g.known) && (!q || (g.name + ' ' + g.aliases.join(' ')).toLowerCase().includes(q)));
  $('#glist').innerHTML = list.map(g => `<div class="gc" data-n="${esc(g.name)}"><div class="spark">${esc(g.country)}</div><h4>${FLAGS[g.country] || ''} ${esc(g.name)}</h4><div class="al">${esc(g.aliases.slice(0, 5).join(' · ')) || '<i>no known aliases</i>'}</div>
  <div class="chips">${g.tags.slice(0, 3).map(t => `<span class="chip t">#${esc(t[0])}</span>`).join('')}</div>
  <div class="row"><span><b>${g.reportCount}</b>reports</span><span><b>${g.iocs}</b>IoCs</span><span><b>${g.techniques.length}</b>TTPs</span><span><b>${esc(ago(g.last))}</b>last seen</span></div></div>`).join('') || '<div class="empty">No actors match.</div>';
}
function openGroup(name) {
  const g = GROUPS.find(x => x.name === name); if (!g) return;
  const reps = g.reports.map(id => repById.get(id)).filter(Boolean);
  const iocs = IOCS.filter(i => i.g.includes(g.name));
  $('#mbody').innerHTML = `<h2>${FLAGS[g.country] || ''} ${esc(g.name)}</h2><div class="muted">${esc(COUNTRY[g.country] || g.country)} · ${esc(g.sponsor)} · first seen ${esc((g.first || '').slice(0, 10))} · last ${esc((g.last || '').slice(0, 10))}</div>
  ${g.aliases.length ? `<h5>Also known as</h5><div class="chips">${g.aliases.map(a => `<span class="chip">${esc(a)}</span>`).join('')}</div>` : ''}
  ${g.techniques.length ? `<h5>Top ATT&amp;CK techniques</h5><div class="chips">${g.techniques.map(([t, n]) => `<a class="chip t" target="_blank" rel="noopener" href="https://attack.mitre.org/techniques/${esc(t.replace('.', '/'))}/">${esc(t)} ${esc(ATTACK[t.split('.')[0]] || '')} ·${n}</a>`).join('')}</div>` : ''}
  <h5>Recent reports (${g.reportCount})</h5>${reps.slice(0, 12).map(r => `<div class="meta" style="margin:6px 0"><span>${esc(r.published.slice(0, 10))}</span><a href="${safeUrl(r.url)}" target="_blank" rel="noopener noreferrer">${esc(r.title)}</a><span>— ${esc(r.source)}</span></div>`).join('')}
  <h5>Indicators attributed (${iocs.length})</h5><div class="ioclist">${iocs.slice(0, 150).map(i => esc(i.t.padEnd(7) + ' ' + defang(i.v, i.t))).join('\n') || 'None extracted yet'}</div>
  ${iocs.length ? `<p><button class="btn" id="gdl">Download ${iocs.length} IoCs (CSV)</button></p>` : ''}`;
  $('#modal').hidden = false; const b = $('#gdl'); if (b) b.onclick = () => dl(`${g.name.replace(/\W+/g, '_')}_iocs.csv`, toCsv(iocs));
}
async function openReportIocs(id) {
  const r = repById.get(id); const iocs = IOCS.filter(i => i.r.includes(id));
  $('#mbody').innerHTML = `<h2>${esc(r.title)}</h2><div class="muted">${esc(r.source)} · ${esc(r.published.slice(0, 10))} · <a href="${safeUrl(r.url)}" target="_blank" rel="noopener noreferrer">open report ↗</a></div>
  <h5>${iocs.length} indicators (defanged)</h5><div class="ioclist">${iocs.map(i => esc(i.t.padEnd(7) + ' ' + defang(i.v, i.t))).join('\n')}</div>
  ${r.techniques.length ? `<h5>ATT&amp;CK</h5><div class="chips">${r.techniques.map(t => `<span class="chip t">${esc(t)}</span>`).join('')}</div>` : ''}
  <p><button class="btn" id="rdl">Download CSV</button></p>`;
  $('#modal').hidden = false; $('#rdl').onclick = () => dl(`report_${id}_iocs.csv`, toCsv(iocs));
}
$('#mclose').onclick = () => $('#modal').hidden = true; $('#modal').onclick = e => { if (e.target.id === 'modal') $('#modal').hidden = true; }; addEventListener('keydown', e => { if (e.key === 'Escape') $('#modal').hidden = true; });

/* ---------- IoC explorer ---------- */
let iFiltered = [], iShown = 0;
function buildIocs() {
  $('#it').innerHTML += Object.keys(META.iocTypes).map(t => `<option>${esc(t)}</option>`).join('');
  const gs = [...new Set(IOCS.flatMap(i => i.g))].sort(); $('#ig').innerHTML += gs.map(g => `<option>${esc(g)}</option>`).join('');
  ['#iq', '#it', '#ig', '#idf'].forEach(s => $(s).addEventListener('input', () => renderIocs(true)));
  $('#imore').onclick = () => renderIocs(false);
  $('#icsv').onclick = () => dl('threatlens_iocs.csv', toCsv(iFiltered)); $('#itxt').onclick = () => dl('threatlens_iocs.txt', iFiltered.map(i => i.v).join('\n') + '\n');
  $('#itable tbody').onclick = e => { const b = e.target.closest('.cp'); if (b) { navigator.clipboard?.writeText(b.dataset.v); b.textContent = '✓'; setTimeout(() => b.textContent = '⧉', 900); } const rr = e.target.closest('[data-r]'); if (rr) { $('#rq').value = ''; const rp = repById.get(rr.dataset.r); if (rp) openReportIocs(rp.id); } };
  $('#bulkgo').onclick = () => {
    const toks = new Set($('#bulk').value.replace(/\[\.\]/g, '.').toLowerCase().split(/[\s,;|"'<>()]+/).filter(x => x.length > 3));
    const map = new Map(IOCS.map(i => [i.v.toLowerCase(), i])); const hit = [...toks].filter(t => map.has(t)).map(t => map.get(t));
    $('#bulkres').innerHTML = `<p><b>${hit.length}</b> of ${toks.size} tokens match known indicators.</p>` + (hit.length ? `<div class="ioclist">${hit.map(i => esc(i.t + '  ' + defang(i.v, i.t) + '   [' + (i.g.join(', ') || 'unattributed') + ']')).join('\n')}</div>` : '');
  };
  renderIocs(true);
}
function renderIocs(reset) {
  if (reset) {
    const q = $('#iq').value.toLowerCase().replace(/\[\.\]/g, '.'), t = $('#it').value, g = $('#ig').value;
    iFiltered = IOCS.filter(i => (!t || i.t === t) && (!g || i.g.includes(g)) && (!q || i.v.toLowerCase().includes(q) || i.g.some(x => x.toLowerCase().includes(q)) || i.r.some(id => (repById.get(id)?.title || '').toLowerCase().includes(q))));
    iShown = 0; $('#itable tbody').innerHTML = ''; $('#icount').textContent = `${fmt(iFiltered.length)} indicators`;
  }
  const d = $('#idf').checked;
  $('#itable tbody').insertAdjacentHTML('beforeend', iFiltered.slice(iShown, iShown + 100).map(i => `<tr><td><span class="ty ${esc(i.t)}">${esc(i.t)}</span></td><td class="v">${esc(d ? defang(i.v, i.t) : i.v)}</td><td>${esc(i.g.slice(0, 2).join(', ')) || '<span class="muted">—</span>'}</td><td>${esc(i.last.slice(0, 10))}</td><td><a href="#iocs" data-r="${esc(i.r[0])}" title="${esc(repById.get(i.r[0])?.title || '')}">${i.r.length}</a></td><td><button class="cp" data-v="${esc(i.v)}" title="Copy (refanged)">⧉</button></td></tr>`).join('')); iShown += 100;
  $('#imore').style.display = iShown < iFiltered.length ? '' : 'none';
}
const toCsv = a => 'type,value,first_seen,last_seen,groups\n' + a.map(i => [i.t, i.v, i.first.slice(0, 10), i.last.slice(0, 10), i.g.join('|')].map(x => `"${String(x).replace(/"/g, '""')}"`).join(',')).join('\n') + '\n';
function dl(name, text) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); }

/* ---------- ATT&CK / KEV / sources ---------- */
function buildAttack() {
  const max = META.techniques[0]?.[1] || 1;
  $('#tech').innerHTML = META.techniques.map(([t, n]) => `<div class="tech"><code>${esc(t)}</code><div><div class="track" style="height:9px;background:#0a1626;border-radius:99px;overflow:hidden"><div class="fill" style="width:${n / max * 100}%;background:linear-gradient(90deg,#a78bfa,#3da5ff)"></div></div><small class="muted">${esc(ATTACK[t] || 'Technique')}</small></div><span class="muted">${n}</span></div>`).join('') || '<div class="muted">No technique IDs found yet.</div>';
}
function buildKev() {
  if (!KEV) { $('#kevlist').innerHTML = '<div class="empty">KEV data unavailable.</div>'; return; }
  $('#kevk').innerHTML = [['KEV catalogue', KEV.total, '--bad'], ['Used by ransomware', KEV.ransomware, '--warn'], ['Showing latest', KEV.latest.length, '--acc2']].map(([l, v, c]) => `<div class="kpi" style="--c:var(${c})"><span>${l}</span><b>${fmt(v)}</b></div>`).join('');
  const draw = () => { const q = $('#kq').value.toLowerCase(); $('#kevlist').innerHTML = KEV.latest.filter(v => !q || (v.cve + v.vendor + v.product + v.name).toLowerCase().includes(q)).map(v => `<div class="kev"><h4><a target="_blank" rel="noopener" href="https://nvd.nist.gov/vuln/detail/${esc(v.cve)}" style="font-family:var(--mono)">${esc(v.cve)}</a> — ${esc(v.vendor)} ${esc(v.product)} ${v.ransomware ? '<span class="chip c">ransomware use</span>' : ''}</h4><div class="meta"><span>added ${esc(v.added)}</span><span>patch due ${esc(v.due)}</span></div><p>${esc(v.name)}. ${esc(v.desc)}</p></div>`).join(''); };
  $('#kq').oninput = draw; draw();
}
function buildSources() {
  $('#shealth').textContent = `${META.totals.sourcesOk} of ${META.totals.sources} sources responded on the last run (${META.runSeconds}s). Failed feeds are retried every run.`;
  $('#slist').innerHTML = META.sources.map(s => `<div class="src"><span class="dot ${s.ok ? '' : 'bad'}"></span><div><b>${esc(s.name)}</b><small>${esc(s.type)} · ${s.ok ? s.items + ' items, ' + s.new + ' new' : esc(s.error)}</small></div></div>`).join('');
}

/* ---------- animated background (network nodes) ---------- */
(function bg() {
  const c = $('#bg'), x = c.getContext('2d'); if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  let W, H, pts; const N = 55;
  const size = () => { W = c.width = innerWidth; H = c.height = innerHeight; pts = Array.from({ length: N }, () => ({ x: Math.random() * W, y: Math.random() * H, vx: (Math.random() - .5) * .25, vy: (Math.random() - .5) * .25 })); };
  size(); addEventListener('resize', size);
  (function f() {
    x.clearRect(0, 0, W, H);
    for (const p of pts) { p.x = (p.x + p.vx + W) % W; p.y = (p.y + p.vy + H) % H; x.fillStyle = '#00e5a8'; x.fillRect(p.x, p.y, 2, 2); }
    for (let i = 0; i < N; i++) for (let k = i + 1; k < N; k++) { const dx = pts[i].x - pts[k].x, dy = pts[i].y - pts[k].y, d = dx * dx + dy * dy; if (d < 16000) { x.strokeStyle = `rgba(61,165,255,${(1 - d / 16000) * .35})`; x.beginPath(); x.moveTo(pts[i].x, pts[i].y); x.lineTo(pts[k].x, pts[k].y); x.stroke(); } }
    requestAnimationFrame(f);
  })();
})();

init();
})();
