/* ThreatLens front-end. All feed-derived strings pass through esc() — feed content is untrusted. */
if (window.top !== window.self) { try { window.top.location = window.self.location; } catch { document.documentElement.innerHTML = ''; } }   // refuse to be framed
(() => {
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const safeUrl = u => /^https?:\/\//i.test(u) ? esc(u) : '#';
const fmt = n => (n ?? 0).toLocaleString();
const TZMODE = (() => { try { return localStorage.getItem('tl_tz') === 'utc' ? 'utc' : 'local'; } catch { return 'local'; } })();
const p2 = n => String(n).padStart(2, '0');
const offsetLabel = () => { const m = -new Date().getTimezoneOffset(), h = Math.trunc(m / 60), mm = Math.abs(m % 60); return 'UTC' + (m >= 0 ? '+' : '-') + Math.abs(h) + (mm ? ':' + p2(mm) : ''); };
const fmtUTC = iso => new Date(iso).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
const fmtLocal = iso => { const d = new Date(iso); return d.getFullYear() + '-' + p2(d.getMonth() + 1) + '-' + p2(d.getDate()) + ' ' + p2(d.getHours()) + ':' + p2(d.getMinutes()) + ' ' + offsetLabel(); };
/* date-only sources (no time of day in the feed) are shown as a plain date, never as a made-up "00:00" */
const dOnly = r => r.dp === 'd' || /T00:00:00\.000Z$/.test(r.published || '');
const fmtDT = (iso, dateOnly) => dateOnly ? new Date(iso).toISOString().slice(0, 10) : (TZMODE === 'utc' ? fmtUTC(iso) : fmtLocal(iso));
const stamp = r => dOnly(r) ? new Date(r.published).toISOString().slice(0, 10) + ' (the source gives a date only, no time of day)' : fmtLocal(r.published) + '  =  ' + fmtUTC(r.published);
const ago = iso => { const m = (Date.now() - new Date(iso)) / 6e4; if (m < 1) return 'just now'; if (m < 60) return Math.floor(m) + ' min ago'; const h = m / 60; if (h < 24) return Math.floor(h) + ' h ago'; const d = h / 24; return d < 2 ? 'yesterday' : Math.floor(d) + ' d ago'; };
const dayAgo = iso => { const n = Math.floor((Date.parse(new Date().toISOString().slice(0, 10)) - Date.parse(iso.slice(0, 10))) / 864e5); return n <= 0 ? 'today' : n === 1 ? 'yesterday' : n + ' d ago'; };
const agoR = r => dOnly(r) ? dayAgo(r.published) : ago(r.published);
const isNew = r => Date.now() - new Date(dOnly(r) ? (r.firstSeen || r.published) : r.published) < 6 * 36e5;
const defang = (v, t) => t === 'url' ? v.replace(/^http/i, 'hxxp').replace(/\./g, '[.]') : (t === 'domain' || t === 'ipv4') ? v.replace(/\./g, '[.]') : t === 'email' ? v.replace('@', '[@]').replace(/\./g, '[.]') : t === 'ipv6' ? v.replace(/:/g, '[:]') : v;
const FLAGS = { RU: '🇷🇺', CN: '🇨🇳', KP: '🇰🇵', IR: '🇮🇷', US: '🇺🇸', IN: '🇮🇳', PK: '🇵🇰', VN: '🇻🇳', BY: '🇧🇾', KR: '🇰🇷', SD: '🇸🇩', Intl: '🌐', '??': '❔' };
const ATTACK = { T1566: 'Phishing', T1059: 'Command & Scripting', T1190: 'Exploit Public-Facing App', T1078: 'Valid Accounts', T1105: 'Ingress Tool Transfer', T1027: 'Obfuscated Files', T1071: 'App Layer Protocol', T1055: 'Process Injection', T1053: 'Scheduled Task', T1547: 'Boot/Logon Autostart', T1036: 'Masquerading', T1070: 'Indicator Removal', T1082: 'System Info Discovery', T1083: 'File & Dir Discovery', T1003: 'OS Credential Dumping', T1021: 'Remote Services', T1486: 'Data Encrypted for Impact', T1041: 'Exfil Over C2', T1204: 'User Execution', T1218: 'System Binary Proxy Exec', T1562: 'Impair Defenses', T1112: 'Modify Registry', T1140: 'Deobfuscate/Decode', T1056: 'Input Capture', T1057: 'Process Discovery', T1012: 'Query Registry', T1018: 'Remote System Discovery', T1033: 'System Owner Discovery', T1046: 'Network Service Discovery', T1074: 'Data Staged', T1090: 'Proxy', T1095: 'Non-App Layer Protocol', T1102: 'Web Service', T1133: 'External Remote Services', T1189: 'Drive-by Compromise', T1195: 'Supply Chain Compromise', T1203: 'Exploitation for Client Exec', T1219: 'Remote Access Software', T1485: 'Data Destruction', T1490: 'Inhibit System Recovery', T1496: 'Resource Hijacking', T1505: 'Server Software Component', T1543: 'Create/Modify System Process', T1546: 'Event Triggered Execution', T1553: 'Subvert Trust Controls', T1560: 'Archive Collected Data', T1567: 'Exfil Over Web Service', T1568: 'Dynamic Resolution', T1573: 'Encrypted Channel', T1574: 'Hijack Execution Flow', T1587: 'Develop Capabilities', T1588: 'Obtain Capabilities', T1589: 'Gather Victim Identity', T1595: 'Active Scanning', T1598: 'Phishing for Information', T1621: 'MFA Request Generation' };
const COUNTRY = { RU: 'Russia', CN: 'China', KP: 'North Korea', IR: 'Iran', US: 'United States', IN: 'India', PK: 'Pakistan', VN: 'Vietnam', BY: 'Belarus', KR: 'South Korea', SD: 'Sudan', Intl: 'eCrime / Intl', '??': 'Unattributed' };

let META, REPORTS = [], GROUPS = [], KEV, IOCS = [], COUNTRIES = [], CVES = {}, repById = new Map();

/* Data is read live from the GitHub repo (updated by the scheduled job), so the site stays fresh without
   a Netlify redeploy. If GitHub is unreachable, the copy bundled with the site is used instead. */
const REMOTE = 'https://raw.githubusercontent.com/johndesanya/threatlens/main/site/';
const LOCAL_DEV = ['localhost', '127.0.0.1'].includes(location.hostname);   // when testing locally, use local files only
async function j(u) {
  for (const base of LOCAL_DEV ? [''] : [REMOTE, '']) {
    try { const r = await fetch(base + u, { cache: 'no-cache' }); if (r.ok) return await r.json(); } catch { /* try next source */ }
  }
  throw new Error(u);
}
const nrm = s => String(s).toLowerCase().replace(/ё/g, 'е').trim();
const cname = c => COUNTRIES.find(x => x.code === c)?.name || c;
/* country codes a search query refers to: "armenia", "армения", "arm", "georgian"… */
function countryCodesFor(q) {
  q = nrm(q); const out = new Set(); if (q.length < 3) return out;
  for (const c of COUNTRIES) if ([c.name, ...c.aliases].some(a => { a = nrm(a); return a === q || a.startsWith(q) || (a.length >= 5 && q.startsWith(a)); })) out.add(c.code);
  return out;
}
async function init() {
  try {
    [META, GROUPS, KEV] = await Promise.all([j('data/meta.json'), j('data/groups.json'), j('data/kev.json').catch(() => null)]);
    REPORTS = (await j('data/reports.json')).reports; repById = new Map(REPORTS.map(r => [r.id, r]));
    REPORTS.forEach(r => { r.countries = r.countries || []; });
    COUNTRIES = await j('data/countries.json').catch(() => []);
    CVES = ((await j('data/cves.json').catch(() => null)) || {}).c || {};
    IOCS = await j('iocs/all.json').catch(() => []);
  } catch (e) {
    $('#overview').innerHTML = '<div class="empty">No data yet. Run <code>node collector/collect.mjs</code> (or trigger a Netlify build) to collect the first batch.</div>'; return;
  }
  const tzb = $('#tzbtn'); tzb.textContent = '🕒 ' + (TZMODE === 'utc' ? 'UTC' : 'Local ' + offsetLabel()); tzb.title = 'Times are shown in ' + (TZMODE === 'utc' ? 'UTC' : 'your local time') + '. Click to switch.'; tzb.onclick = () => { try { localStorage.setItem('tl_tz', TZMODE === 'utc' ? 'local' : 'utc'); } catch { /* ignore */ } location.reload(); };
  const tick = () => { $('#updated').textContent = 'data ' + fmtDT(META.updated) + ' · ' + ago(META.updated); };
  tick(); setInterval(tick, 30000); watchForUpdates();
  const age = (Date.now() - new Date(META.updated)) / 36e5; if (age > 3) { $('#live').textContent = 'STALE'; $('#live').style.color = 'var(--warn)'; $('#live').style.borderColor = 'var(--warn)'; }
  buildOverview(); buildReports(); buildGroups(); buildIocs(); buildAttack(); buildKev(); buildSources(); buildVisit(); route();
}

/* poll meta.json every 3 minutes; if the collector published newer data, offer a one-click refresh */
function watchForUpdates() {
  setInterval(async () => {
    try { const m = await j('data/meta.json'); if (m.updated !== META.updated && !$('#fresh')) { const b = document.createElement('div'); b.id = 'fresh'; b.innerHTML = 'New intelligence has been collected. <button id="freshgo">Refresh now</button>'; document.body.appendChild(b); $('#freshgo').onclick = () => location.reload(); } } catch { /* offline: ignore */ }
  }, 180000);
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
  $('#kpis').innerHTML = [['Reports tracked', t.reports, `+${REPORTS.filter(r => Date.now() - new Date(r.published) < 864e5).length} in 24h · +${t.reports7d} this week`, '--acc2'], ['Threat actors', t.groups, 'attributed', '--vio'], ['Unique IoCs', t.iocs, `+${fmt(t.iocsThisRun)} last run`, '--warn'], ['CVEs referenced', t.cves, KEV ? fmt(KEV.total) + ' in CISA KEV' : '', '--bad'], ['Live sources', `${t.sourcesOk}/${t.sources}`, 'feeds healthy', '--acc']]
    .map(([l, v, s, c]) => `<div class="kpi" style="--c:var(${c})"><span>${l}</span><b>${typeof v === 'number' ? fmt(v) : esc(v)}</b><small>${esc(s)}</small></div>`).join('');
  dailyChart();
  hbars('#chartGroups', GROUPS.slice(0, 10).map(g => [g.name, g.reportCount, (FLAGS[g.country] || '') + ' ']), r => openGroup(r[0]));
  hbars('#chartCountry', Object.entries(META.countries).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([c, n]) => [COUNTRY[c] || c, n, (FLAGS[c] || '') + ' ']), null, 'linear-gradient(90deg,#a78bfa,#3da5ff)');
  hbars('#chartIoc', Object.entries(META.iocTypes).sort((a, b) => b[1] - a[1]).map(([k, n]) => [k, n]), r => { $('#it').value = r[0]; show('iocs'); renderIocs(true); }, 'linear-gradient(90deg,#ffb020,#ff4d6d)');
  $('#chartTags').innerHTML = Object.entries(META.tags).sort((a, b) => b[1] - a[1]).slice(0, 16).map(([k, n]) => `<span data-tag="${esc(k)}" style="font-size:${11 + Math.min(8, n / 12)}px">${esc(k)} <b>${n}</b></span>`).join('');
  $('#chartTags').onclick = e => { const s = e.target.closest('span'); if (s) { resetFilters(); $('#rtag').value = s.dataset.tag; $('#rrange').value = '9999'; show('reports'); renderReports(true); } };
  $('#latestReports').innerHTML = groupStories(REPORTS.slice(0, 80)).slice(0, 8).map(g => repHtml(g.lead, g.others)).join('');
  $('#latestReports').onclick = repClick;
  $('#topReports').innerHTML = [...REPORTS].filter(r => Date.now() - new Date(r.published) < 30 * 864e5).sort((a, b) => b.score - a.score).slice(0, 7).map(r => repHtml(r)).join('');
  const tr = META.trending || [];
  $('#topCves').innerHTML = tr.length ? tr.slice(0, 12).map(x => `<div class="tcve" data-cve="${esc(x.cve)}"><div><b class="mono">${esc(x.cve)}</b>${cveBadges(x.cve)}</div><small>${x.m24} reports in 24 h · ${x.m72} in 72 h · ${x.src} sources · latest ${ago(x.last)}</small></div>`).join('')
    : META.topCves.slice(0, 14).map(c => `<div class="tcve" data-cve="${esc(c.cve)}"><div><b class="mono">${esc(c.cve)}</b>${cveBadges(c.cve)}</div><small>${c.n} reports</small></div>`).join('');
  $('#topCves').onclick = e => { const x = e.target.closest('[data-cve]'); if (x) openCve(x.dataset.cve); };
  $('#q').oninput = lookup;
  buildRegion();
}
/* "Countries in the news" chart + one-click regional focus */
const FOCUS = ['AM', 'GE', 'AZ', 'TR', 'KZ', 'UZ', 'RU', 'UA', 'BY', 'IR', 'IL', 'CN', 'KP', 'US', 'GB', 'DE', 'FR', 'PL'];
function buildRegion() {
  const m = META.mentions || {};
  const all = {}; REPORTS.forEach(r => r.countries.forEach(c => { all[c] = (all[c] || 0) + 1; }));
  hbars('#chartMention', Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([c, n]) => [cname(c), n, '']), r => { const c = COUNTRIES.find(x => x.name === r[0]); if (c) gotoCountry(c.code); }, 'linear-gradient(90deg,#00e5a8,#3da5ff)');
  $('#region').innerHTML = FOCUS.map(c => `<button class="rbtn" data-c="${esc(c)}">${esc(cname(c))} <b>${all[c] || 0}</b></button>`).join('');
  $('#region').onclick = e => { const b = e.target.closest('[data-c]'); if (b) gotoCountry(b.dataset.c); };
}
function resetFilters() {
  ['#rq', '#rsrc', '#rtype', '#rtag', '#rcountry'].forEach(s => { $(s).value = ''; });
  $('#rrange').value = '30'; $('#rsort').value = 'date';
  ['#rapt', '#rioc', '#rnew'].forEach(s => { $(s).checked = false; });
}
function gotoCountry(code) { resetFilters(); $('#rcountry').value = code; $('#rrange').value = '9999'; show('reports'); renderReports(true); }
function lookup() {
  const q = $('#q').value.trim().toLowerCase().replace(/\[\.\]/g, '.'); const out = $('#qres'); if (q.length < 3) { out.innerHTML = ''; return; }
  const hits = [];
  GROUPS.filter(g => (g.name + ' ' + g.aliases.join(' ')).toLowerCase().includes(q)).slice(0, 4).forEach(g => hits.push(`<div class="hit" data-g="${esc(g.name)}">${FLAGS[g.country] || ''} <b>${esc(g.name)}</b> <span class="muted">${g.reportCount} reports</span></div>`));
  IOCS.filter(i => i.v.includes(q)).slice(0, 5).forEach(i => hits.push(`<div class="hit" data-i="${esc(i.v)}"><span class="ty ${esc(i.t)}">${esc(i.t)}</span> <code>${esc(defang(i.v, i.t)).slice(0, 60)}</code> <span class="muted">${esc(i.g.slice(0, 2).join(', '))}</span></div>`));
  if (/^cve-/.test(q)) { const n = REPORTS.filter(r => r.cves.some(c => c.toLowerCase() === q)).length; hits.push(`<div class="hit" data-cve="${esc(q)}">🔥 <b>${esc(q.toUpperCase())}</b> ${cveBadges(q.toUpperCase())} <span class="muted">mentioned in ${n} reports</span></div>`); }
  countryCodesFor(q).forEach(c => { const n = REPORTS.filter(r => r.countries.includes(c)).length; hits.unshift(`<div class="hit" data-c="${esc(c)}">🌍 <b>${esc(cname(c))}</b> <span class="muted">${n} reports mention it</span></div>`); });
  out.innerHTML = hits.join('') || '<div class="muted" style="padding:6px">No match</div>';
}
$('#qres').onclick = e => { const h = e.target.closest('.hit'); if (!h) return; if (h.dataset.c) return gotoCountry(h.dataset.c); if (h.dataset.cve) return openCve(h.dataset.cve); if (h.dataset.g) openGroup(h.dataset.g); else if (h.dataset.i) { $('#iq').value = h.dataset.i; show('iocs'); renderIocs(true); } else { resetFilters(); $('#rq').value = h.dataset.r; $('#rrange').value = '9999'; show('reports'); renderReports(true); } };

/* ---------- CVE scores: CVSS + EPSS + KEV ---------- */
const sevClass = s => s >= 9 ? 'crit' : s >= 7 ? 'high' : s >= 4 ? 'med' : 'low';
const pct = e => (e * 100).toFixed(e >= 0.1 ? 0 : 1) + '%';
function cveBadges(c) {
  const d = CVES[c] || {}, b = [];
  if (typeof d.s === 'number') b.push(`<b class="sev ${sevClass(d.s)}" title="CVSS base score ${d.s} ${esc(d.v || '')}">${d.s.toFixed(1)}</b>`);
  if (typeof d.e === 'number') b.push(`<i class="epss ${d.e >= 0.5 ? 'hi' : d.e >= 0.1 ? 'mid' : ''}" title="EPSS: ${esc((d.e * 100).toFixed(2))}% probability of exploitation in the next 30 days">${pct(d.e)}</i>`);
  if (d.k) b.push('<u class="kevb" title="Listed in the CISA Known Exploited Vulnerabilities catalogue">KEV</u>');
  return b.join('');
}
const cveChip = c => `<span class="chip c" data-cve="${esc(c)}" title="Click for scores and reports">${esc(c)}${cveBadges(c)}</span>`;
function openCve(c) {
  c = /^CVE-\d{4}-\d{4,7}$/i.test(c) ? c.toUpperCase() : ''; if (!c) return;
  const d = CVES[c] || {}, all = REPORTS.filter(r => r.cves.includes(c));
  $('#mbody').innerHTML = `<h2 style="font-family:var(--mono)">${esc(c)}</h2><div class="chips">${cveBadges(c) || '<span class="muted">No score published yet</span>'}</div>
  <h5>Scores</h5><div class="muted">CVSS: <b>${typeof d.s === 'number' ? d.s.toFixed(1) + ' ' + esc(d.v || '') : 'not published'}</b> · EPSS (chance of exploitation within 30 days): <b>${typeof d.e === 'number' ? (d.e * 100).toFixed(2) + '%' : 'n/a'}</b>${typeof d.p === 'number' ? ' (more likely than ' + (d.p * 100).toFixed(1) + '% of all CVEs)' : ''} · ${d.k ? '<b style="color:var(--bad)">in CISA KEV: exploited in the wild</b>' : 'not in CISA KEV'}</div>
  <h5>Look it up</h5><div class="chips"><a class="chip t" target="_blank" rel="noopener noreferrer" href="https://nvd.nist.gov/vuln/detail/${esc(c)}">NVD</a><a class="chip t" target="_blank" rel="noopener noreferrer" href="https://www.cve.org/CVERecord?id=${esc(c)}">CVE.org</a><a class="chip t" target="_blank" rel="noopener noreferrer" href="https://epss.empiricalsecurity.com/">EPSS explorer</a><a class="chip t" target="_blank" rel="noopener noreferrer" href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV</a></div>
  <h5>Reports mentioning it (${all.length})</h5>${all.slice(0, 15).map(r => `<div class="meta" style="margin:6px 0"><span>${esc(fmtDT(r.published, dOnly(r)))}</span><a href="${safeUrl(r.url)}" target="_blank" rel="noopener noreferrer" dir="auto">${esc(r.title)}</a><span>— ${esc(r.source)}</span></div>`).join('') || '<div class="muted">None yet.</div>'}`;
  $('#modal').hidden = false;
}

/* ---------- "new since your last visit" (kept only in this browser's localStorage) ---------- */
const VISIT = (() => {
  try {
    const now = Date.now(), last = +localStorage.getItem('tl_last') || 0; let base = +localStorage.getItem('tl_base') || 0;
    if (!last) base = now; else if (now - last > 30 * 60e3) base = last;       // a visit more than 30 min after the last one starts a new session
    localStorage.setItem('tl_base', String(base)); localStorage.setItem('tl_last', String(now));
    return { base, ok: true };
  } catch { return { base: Date.now(), ok: false }; }
})();
const isUnread = r => new Date(r.firstSeen || r.published).getTime() > VISIT.base && new Date(r.published).getTime() > VISIT.base - 48 * 36e5;
function buildVisit() {
  const n = REPORTS.filter(isUnread).length, p = $('#newpill');
  p.hidden = !(n > 0 && VISIT.ok);
  p.textContent = '🔔 ' + fmt(n) + ' new since your last visit';
  p.onclick = () => { resetFilters(); $('#rnew').checked = true; $('#rrange').value = '9999'; show('reports'); renderReports(true); };
  document.title = (n > 0 && VISIT.ok ? '(' + (n > 99 ? '99+' : n) + ') ' : '') + 'ThreatLens — Live Threat Intelligence';
  $('#rread').hidden = !(n > 0 && VISIT.ok);
}
function markRead() { try { localStorage.setItem('tl_base', String(Date.now())); } catch { /* ignore */ } VISIT.base = Date.now(); resetFilters(); buildVisit(); renderReports(true); }

/* ---------- duplicate coverage: one card per story ---------- */
const TYPE_PRI = { research: 4, gov: 3, vendor: 2, news: 1, regional: 0 };
const leadRank = r => (TYPE_PRI[r.sourceType] || 0) * 10 + (r.deep ? 3 : 0) + (r.iocTotal ? 4 : 0) + (r.score || 0) / 20;
function groupStories(list) {
  const out = [], by = new Map();
  for (const r of list) {
    if (r.story && by.has(r.story)) { by.get(r.story).all.push(r); continue; }
    const g = { all: [r] }; out.push(g); if (r.story) by.set(r.story, g);
  }
  for (const g of out) {
    g.all.sort((a, b) => leadRank(b) - leadRank(a) || (a.published < b.published ? -1 : 1));
    g.lead = g.all[0]; g.others = g.all.slice(1).sort((a, b) => (a.published < b.published ? 1 : -1));
  }
  return out;
}
const alsoHtml = others => `<details class="also"><summary>+${others.length} more source${others.length > 1 ? 's' : ''} covering this story</summary>${others.map(o => `<div class="meta2"><a href="${safeUrl(o.url)}" target="_blank" rel="noopener noreferrer" dir="auto">${esc(o.title)}</a><span>${esc(o.source)} · ${esc(fmtDT(o.published, dOnly(o)))}</span></div>`).join('')}</details>`;

/* ---------- reports ---------- */
function scoreColor(s) { return s >= 70 ? 'var(--bad)' : s >= 40 ? 'var(--warn)' : 'var(--acc2)'; }
function repHtml(r, others = []) {
  const ic = Object.entries(r.iocCounts || {}).map(([k, v]) => `${v} ${k}`).join(' · '), unread = isUnread(r) || others.some(isUnread);
  return `<article class="rep${unread ? ' unread' : ''}" data-id="${esc(r.id)}"><div class="score" style="--p:${r.score};--c:${scoreColor(r.score)}" data-s="${r.score}" title="Threat score"></div><div>
  <h4><a href="${safeUrl(r.url)}" target="_blank" rel="noopener noreferrer" dir="auto">${esc(r.title)}</a></h4>
  <div class="meta"><span>${esc(r.source)}</span><span class="dt" title="Published: ${esc(stamp(r))}. Date taken from the ${r.dateSrc === 'page' ? 'article page' : 'feed'}. First collected by ThreatLens: ${esc(r.firstSeen ? fmtDT(r.firstSeen) : (r.collected || ''))}">🕒 ${esc(fmtDT(r.published, dOnly(r)))} · ${agoR(r)}</span>${isNew(r) ? '<span class="new">NEW</span>' : ''}${unread ? '<span class="unreadDot" title="New since your last visit">●</span>' : ''}${r.lang ? `<span class="flag" title="Original language">${esc(String(r.lang).toUpperCase())}</span>` : ''}${r.sourceType === 'gov' ? '<span class="flag">GOV</span>' : ''}${r.sourceType === 'vendor' ? '<span class="flag">VENDOR</span>' : ''}${r.deep ? '' : '<span title="Only the feed teaser was analysed">teaser</span>'}</div>
  ${r.en && r.en.length ? `<p class="en" title="English keywords found in the original-language text">EN: ${esc(r.en.join(' · '))}</p>` : ''}
  ${r.summary ? `<p class="sum" dir="auto">${esc(r.summary.slice(0, 230))}…</p>` : ''}
  <div class="chips">${r.groups.map(g => `<span class="chip g" data-g="${esc(g.name)}">${FLAGS[g.country] || ''} ${esc(g.name)}</span>`).join('')}${r.countries.slice(0, 4).map(c => `<span class="chip k" data-c="${esc(c)}" title="Reports mentioning ${esc(cname(c))}">${esc(cname(c))}</span>`).join('')}${r.iocTotal ? `<span class="chip i" data-ioc="${esc(r.id)}" title="${esc(ic)}">⚑ ${r.iocTotal} IoCs</span>` : ''}${r.cves.slice(0, 4).map(cveChip).join('')}${r.cves.length > 4 ? `<span class="chip">+${r.cves.length - 4} CVEs</span>` : ''}${r.tags.slice(0, 4).map(t => `<span class="chip t" data-tag="${esc(t)}">#${esc(t)}</span>`).join('')}</div>
  ${others.length ? alsoHtml(others) : ''}</div></article>`;
}
let rShown = 0, rFiltered = [], rGroups = [];
function buildReports() {
  const src = [...new Set(REPORTS.map(r => r.source))].sort(); $('#rsrc').innerHTML += src.map(s => `<option>${esc(s)}</option>`).join('');
  $('#rtag').innerHTML += Object.keys(META.tags).sort().map(s => `<option>${esc(s)}</option>`).join('');
  const cnt = {}; REPORTS.forEach(r => r.countries.forEach(c => { cnt[c] = (cnt[c] || 0) + 1; }));
  $('#rcountry').innerHTML += Object.entries(cnt).sort((a, b) => b[1] - a[1]).map(([c, n]) => `<option value="${esc(c)}">${esc(cname(c))} (${n})</option>`).join('');
  ['#rq', '#rsrc', '#rtype', '#rtag', '#rcountry', '#rrange', '#rsort', '#rapt', '#rioc', '#rgroup', '#rnew'].forEach(s => $(s).addEventListener('input', () => renderReports(true)));
  $('#rmore').onclick = () => renderReports(false); $('#rlist').onclick = repClick; $('#topReports').onclick = repClick; $('#rread').onclick = markRead; $('#rreset').onclick = () => { resetFilters(); renderReports(true); };
  renderReports(true);
}
function repClick(e) {
  const cv = e.target.closest('[data-cve]'); if (cv) return openCve(cv.dataset.cve);
  const g = e.target.closest('[data-g]'); if (g) return openGroup(g.dataset.g);
  const k = e.target.closest('[data-c]'); if (k) return gotoCountry(k.dataset.c);
  const t = e.target.closest('[data-tag]'); if (t) { resetFilters(); $('#rtag').value = t.dataset.tag; $('#rrange').value = '9999'; show('reports'); return renderReports(true); }
  const i = e.target.closest('[data-ioc]'); if (i) openReportIocs(i.dataset.ioc);
}
function renderReports(reset) {
  if (reset) {
    const q = nrm($('#rq').value), cut = Date.now() - +$('#rrange').value * 864e5, cc = $('#rcountry').value;
    const qCodes = countryCodesFor(q);   // "armenia" / "армения" / "arm" -> reports tagged with that country
    rFiltered = REPORTS.filter(r => new Date(r.published) >= cut && (!$('#rsrc').value || r.source === $('#rsrc').value) && (!$('#rtype').value || r.sourceType === $('#rtype').value) && (!$('#rtag').value || r.tags.includes($('#rtag').value)) && (!cc || r.countries.includes(cc)) && (!$('#rapt').checked || r.groups.length) && (!$('#rioc').checked || r.iocTotal) && (!$('#rnew').checked || isUnread(r)) &&
      (!q || nrm(r.title + ' ' + r.summary + ' ' + r.source + ' ' + r.groups.map(g => g.name).join(' ') + ' ' + r.cves.join(' ') + ' ' + r.countries.map(cname).join(' ') + ' ' + (r.en || []).join(' ')).includes(q) || r.countries.some(c => qCodes.has(c))));
    if ($('#rsort').value === 'score') rFiltered.sort((a, b) => b.score - a.score || (a.published < b.published ? 1 : -1));
    // when searching by country, reports where that country is the main subject come first
    const want = cc ? new Set([cc]) : qCodes;
    if (want.size && $('#rsort').value !== 'score') { const rank = r => { let m = 50; r.countries.forEach((c, i) => { if (want.has(c) && i < m) m = i; }); return m; }; rFiltered.sort((a, b) => rank(a) - rank(b) || (a.published < b.published ? 1 : -1)); }
    rGroups = $('#rgroup').checked ? groupStories(rFiltered) : rFiltered.map(r => ({ lead: r, others: [] }));
    rShown = 0; $('#rlist').innerHTML = '';
    $('#rcount').textContent = `${fmt(rFiltered.length)} reports` + ($('#rgroup').checked ? ` · ${fmt(rGroups.length)} stories` : '');
  }
  $('#rlist').insertAdjacentHTML('beforeend', rGroups.slice(rShown, rShown + 25).map(g => repHtml(g.lead, g.others)).join('')); rShown += 25;
  $('#rmore').style.display = rShown < rGroups.length ? '' : 'none';
  if (!rGroups.length) $('#rlist').innerHTML = '<div class="empty">No reports match.</div>';
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
  $('#itable tbody').insertAdjacentHTML('beforeend', iFiltered.slice(iShown, iShown + 100).map(i => `<tr><td><span class="ty ${esc(i.t)}">${esc(i.t)}</span></td><td class="v">${esc(d ? defang(i.v, i.t) : i.v)}</td><td>${esc(i.g.slice(0, 2).join(', ')) || '<span class="muted">—</span>'}</td><td title="first seen ${esc(i.first.slice(0, 10))}">${esc(i.last.slice(0, 10))}</td><td>${i.r.length ? `<a href="#iocs" data-r="${esc(i.r[0])}" title="${esc(repById.get(i.r[0])?.title || '')}">${i.r.length}</a>` : ''}${(i.s || []).slice(0, 1).map(f => `<span class="chip i" title="${esc(f)}">feed: ${esc(f.split(' ')[0])}</span>`).join('')}</td><td><button class="cp" data-v="${esc(i.v)}" title="Copy (refanged)">⧉</button></td></tr>`).join('')); iShown += 100;
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
  const draw = () => { const q = $('#kq').value.toLowerCase(); $('#kevlist').innerHTML = KEV.latest.filter(v => !q || (v.cve + v.vendor + v.product + v.name).toLowerCase().includes(q)).map(v => `<div class="kev"><h4><a target="_blank" rel="noopener" href="https://nvd.nist.gov/vuln/detail/${esc(v.cve)}" style="font-family:var(--mono)">${esc(v.cve)}</a> ${cveBadges(v.cve)} — ${esc(v.vendor)} ${esc(v.product)} ${v.ransomware ? '<span class="chip c">ransomware use</span>' : ''}</h4><div class="meta"><span>added ${esc(v.added)}</span><span>patch due ${esc(v.due)}</span></div><p>${esc(v.name)}. ${esc(v.desc)}</p></div>`).join(''); };
  $('#kq').oninput = draw; draw();
}
function buildSources() {
  const t = META.totals, bad = META.sources.filter(s => !s.ok).length;
  $('#shealth').textContent = `${t.sourcesOk} of ${t.sources} sources responded on the last run (${META.runSeconds}s)${bad ? ' - ' + bad + ' failing (retried every run)' : ''}. Each source shows when its newest post was published.`;
  const card = s => `<div class="src"><span class="dot ${s.ok ? '' : 'bad'}"></span><div><b>${esc(s.name)}</b><small>${esc(s.type)} · ${s.ok ? s.items + ' items, ' + s.new + ' new' + (s.newest ? ' · latest post ' + ago(s.newest) : '') : esc(s.error) + (s.since ? ' · failing since ' + esc(s.since.slice(0, 16).replace('T', ' ')) : '')}</small></div></div>`;
  const ord = [...META.sources].sort((a, b) => (a.ok - b.ok) || String(b.newest || '').localeCompare(String(a.newest || '')));
  $('#slist').innerHTML = ord.map(card).join('');
  const lf = META.iocFeeds || [];
  $('#ioclist2').innerHTML = lf.map(f => `<div class="src"><span class="dot ${f.ok ? '' : 'bad'}"></span><div><b>${esc(f.name)}</b><small>${esc(f.type)} · ${f.ok ? f.listed + ' listed, ' + f.items + ' kept' : esc(f.error || 'failed')}</small></div></div>`).join('') || '<div class="muted">No direct IoC feeds configured.</div>';
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
