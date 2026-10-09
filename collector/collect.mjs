#!/usr/bin/env node
/**
 * ThreatLens collector
 * --------------------
 * Pulls public threat-intel feeds (vendor research blogs, CERT advisories, news),
 * attributes each report to APT / crimeware groups, extracts IoCs + MITRE ATT&CK
 * technique IDs + CVEs, and writes everything as static JSON/CSV/TXT under /site
 * so Netlify can serve it. IoCs are stored in their own folder: site/iocs/
 *
 * Zero dependencies. Needs Node 18+ (global fetch).
 *   node collector/collect.mjs            # normal incremental run
 *   FULL=1 node collector/collect.mjs     # ignore cache, re-process everything
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SITE = path.join(ROOT, 'site');
const DATA = path.join(SITE, 'data');
const IOCS = path.join(SITE, 'iocs');

const MAX_AGE_DAYS = +process.env.MAX_AGE_DAYS || 120;   // ignore feed items older than this
const RETAIN_DAYS = +process.env.RETAIN_DAYS || 365;     // keep reports this long
const MAX_DEEP_FETCH = +process.env.MAX_DEEP_FETCH || 260; // article pages fetched per run
const CONCURRENCY = 8;
const UA = 'Mozilla/5.0 (compatible; ThreatLensBot/1.0; +https://github.com/threatlens)';
const FULL = !!process.env.FULL;

const readJson = (p, d) => { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return d; } };
const writeJson = (p, o, pretty) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, JSON.stringify(o, null, pretty ? 2 : 0)); };
const writeText = (p, s) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, s); };
const sha1 = s => crypto.createHash('sha1').update(s).digest('hex');
const log = (...a) => console.log(...a);

/* ------------------------------------------------------------------ helpers */
async function pool(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; try { out[k] = await fn(items[k], k); } catch (e) { out[k] = { error: String(e.message || e) }; } }
  }));
  return out;
}
async function get(url, timeout = 25000) {
  const r = await fetch(url, { headers: { 'User-Agent': UA, Accept: 'text/html,application/xml,application/rss+xml,application/json,*/*' }, redirect: 'follow', signal: AbortSignal.timeout(timeout) });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return await r.text();
}
const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ndash: '-', mdash: '-', hellip: '...', rsquo: "'", lsquo: "'", ldquo: '"', rdquo: '"' };
const decode = s => s.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (m, e) => {
  if (e[0] === '#') { const c = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); try { return String.fromCodePoint(c); } catch { return ' '; } }
  return ENT[e.toLowerCase()] ?? m;
});
function htmlToText(h) {
  return decode(h
    .replace(/<(script|style|noscript|svg|nav|footer|header|form)[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<\/(p|div|li|tr|h[1-6]|pre|section|article|table|blockquote)>|<br\s*\/?>/gi, '\n')
    .replace(/<[^>]+>/g, ' '))
    .replace(/[ \t\f\v ]+/g, ' ').replace(/ *\n */g, '\n').replace(/\n{3,}/g, '\n\n').trim();
}
function articleBody(html) {
  const m = html.match(/<article[\s\S]*?<\/article>/i) || html.match(/<main[\s\S]*?<\/main>/i);
  return htmlToText(m ? m[0] : html);
}

/* ------------------------------------------------------------- feed parsing */
const unwrap = s => { const m = s.match(/^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/); return m ? m[1] : decode(s); };
const tag = (b, n) => { const m = b.match(new RegExp(`<${n}(?:\\s[^>]*)?>([\\s\\S]*?)</${n}>`, 'i')); return m ? unwrap(m[1]).trim() : ''; };
function parseFeed(xml) {
  const blocks = xml.match(/<(item|entry)[\s>][\s\S]*?<\/\1>/gi) || [];
  return blocks.map(b => {
    let link = '';
    const alt = b.match(/<link[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)["']/i) || b.match(/<link[^>]*href=["']([^"']+)["'][^>]*\/?>/i);
    link = alt ? decode(alt[1]) : tag(b, 'link');
    if (!link) link = tag(b, 'guid');
    const cats = [...b.matchAll(/<category[^>]*?(?:term=["']([^"']+)["'][^>]*\/?>|>([\s\S]*?)<\/category>)/gi)].map(m => unwrap(m[1] || m[2] || '').trim()).filter(Boolean);
    const date = tag(b, 'pubDate') || tag(b, 'published') || tag(b, 'updated') || tag(b, 'dc:date');
    const content = tag(b, 'content:encoded') || tag(b, 'content') || tag(b, 'description') || tag(b, 'summary');
    return { title: htmlToText(tag(b, 'title')), link: link.trim(), date, cats, html: content };
  }).filter(e => e.title && /^https?:/.test(e.link));
}
const toDate = s => { const d = new Date(s); return isNaN(d) ? null : d; };

/* ------------------------------------------------------------ IoC extraction */
const BENIGN = new Set(`anthropic.com claude.ai openai.com chatgpt.com langchain.com huggingface.co powerbi.com atlassian.net atlassian.com notion.so figma.com stackoverflow.com google.com googleapis.com gstatic.com youtube.com youtu.be microsoft.com windows.com windowsupdate.com live.com office.com office365.com outlook.com azure.com azureedge.net msn.com bing.com github.com githubusercontent.com gitlab.com bitbucket.org twitter.com x.com t.co facebook.com linkedin.com instagram.com reddit.com medium.com wordpress.com wikipedia.org mozilla.org apple.com icloud.com amazon.com amazonaws.com cloudfront.net cloudflare.com akamai.net akamaihd.net fastly.net adobe.com oracle.com java.com python.org nodejs.org npmjs.com pypi.org virustotal.com hybrid-analysis.com any.run joesandbox.com urlscan.io shodan.io censys.io mitre.org attack.mitre.org nist.gov nvd.nist.gov cve.org cisa.gov fbi.gov ic3.gov ncsc.gov.uk us-cert.gov europa.eu paloaltonetworks.com talosintelligence.com cisco.com kaspersky.com securelist.com eset.com welivesecurity.com sophos.com symantec.com broadcom.com trendmicro.com checkpoint.com crowdstrike.com mandiant.com sentinelone.com fortinet.com malwarebytes.com recordedfuture.com proofpoint.com volexity.com elastic.co bitdefender.com avast.com mcafee.com zscaler.com huntress.com sekoia.io thedfirreport.com bleepingcomputer.com thehackernews.com krebsonsecurity.com securityweek.com darkreading.com therecord.media wired.com reuters.com bbc.com bbc.co.uk nytimes.com washingtonpost.com theregister.com arstechnica.com zdnet.com vice.com vimeo.com slack.com zoom.us dropbox.com box.com sharepoint.com onedrive.com drive.google.com docs.google.com t.me telegram.org discord.com discord.gg pastebin.com bit.ly goo.gl tinyurl.com ow.ly feedburner.com w3.org example.com example.org example.net localhost schema.org gravatar.com wp.com cdn.jsdelivr.net jsdelivr.net unpkg.com cloudflare-dns.com dns.google opendns.com quad9.net archive.org web.archive.org virusbulletin.com blogspot.com tumblr.com substack.com gmail.com yahoo.com hotmail.com protonmail.com proton.me mail.com`.split(/\s+/));
const TLDS = new Set(`com net org io info biz xyz top online site club live shop store tech app dev cloud pro icu vip cn ru ir kp kr jp in de fr uk us co me tv cc ws to su ua by kz tk ml ga cf gq pw link click work page space website fun one ink cyou buzz sbs bond rest cam monster today life world network systems services solutions digital email support center agency news media group company ltd inc tel mobi name eu nl se no fi dk pl cz ro bg hu gr tr il sa ae eg pk bd vn th id my sg ph hk tw au nz br ar mx cl pe za ng ke ma tn dz ly sy iq lb jo af cu ve it es pt at ch be ie lt lv ee rs hr si sk md am az ge kg uz tj tm mn la kh mm np lk bt ir cx gg im je sx gl nu st sh ac io vc bz tc ms ag gd lc dm kn xn`.split(/\s+/));
const SUSP_EXT = /\.(exe|dll|zip|rar|7z|ps1|sh|js|hta|bat|vbs|bin|msi|iso|lnk|doc|docx|xls|xlsx|jar|scr|elf|apk|php)(\?|$)/i;
const EXCLUDE_IP = new Set(['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '0.0.0.0', '255.255.255.255', '208.67.222.222', '208.67.220.220']);
const ZONE_RE = /(indicators? of compromise|\bIOCs?\b|\bIoCs\b|network indicators|host indicators|\bC2s?\b|\bC&C\b|command[- ]and[- ]control|infrastructure|malicious (?:domains?|ips?|urls?)|appendix)/gi;
const CTX_RE = /\b(ip|address|c2|c&c|server|host|domain|connect|beacon|download|payload|infrastructure|resolve|contact|communicat|exfil|callback|staging|hosted)/i;

function refang(t) {
  return t.replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\\\./gi, '.').replace(/h[xX]{2}ps?/g, m => 'http' + (m.toLowerCase().endsWith('s') ? 's' : ''))
    .replace(/\[:\/\/\]|\[:\]/g, m => (m === '[:]' ? ':' : '://')).replace(/\[@\]|\[at\]|\(at\)/gi, '@').replace(/\[\/\]/g, '/');
}
const isPrivateIp = ip => {
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || a === 0 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19));
};
const regDomain = h => { const p = h.split('.'); return p.length > 2 && !/^(co|com|org|net|gov|ac)$/.test(p[p.length - 2]) ? p.slice(-2).join('.') : p.length > 3 ? p.slice(-3).join('.') : h; };
const isBenign = h => { h = h.toLowerCase(); if (BENIGN.has(h)) return true; const p = h.split('.'); for (let i = 1; i < p.length - 1; i++) if (BENIGN.has(p.slice(i).join('.'))) return true; return false; };

function extractIocs(raw, ownHost) {
  const t = refang(raw);
  const zones = []; let zm;
  ZONE_RE.lastIndex = 0;
  while ((zm = ZONE_RE.exec(t))) zones.push([zm.index, zm.index + 3500]);
  const inZone = i => zones.some(([a, b]) => i >= a && i <= b);
  const defanged = v => { const dv = v.replace(/\./g, '[.]'); return raw.includes(dv) || raw.includes(v.replace(/\./g, '(.)')) || raw.includes(v.replace(/\./g, '[dot]')) || raw.includes(v.replace(/^https?/, 'hxxp').replace(/\./g, '[.]')); };
  const ok = (v, i) => defanged(v) || inZone(i) || CTX_RE.test(t.slice(Math.max(0, i - 90), i + v.length + 90));
  const own = ownHost ? regDomain(ownHost) : '';
  const out = { ipv4: new Set(), domain: new Set(), url: new Set(), md5: new Set(), sha1: new Set(), sha256: new Set(), email: new Set() };
  let m;

  const hashRe = /\b[a-fA-F0-9]{32,64}\b/g;
  while ((m = hashRe.exec(t))) {
    const h = m[0].toLowerCase(); const L = h.length;
    if (L !== 32 && L !== 40 && L !== 64) continue;
    if (!/[0-9]/.test(h) || !/[a-f]/.test(h) || /^(.)\1+$/.test(h)) continue;
    out[L === 32 ? 'md5' : L === 40 ? 'sha1' : 'sha256'].add(h);
  }
  const ipRe = /(?<![\w.\/-])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w-]|\.\d)/g;
  while ((m = ipRe.exec(t))) { const ip = m[0]; if (EXCLUDE_IP.has(ip) || isPrivateIp(ip)) continue; if (/\.0$/.test(ip) && !defanged(ip)) continue; if (ok(ip, m.index)) out.ipv4.add(ip); }

  const urlRe = /\bhttps?:\/\/[^\s"'<>()\[\]{},;|\\`]+/gi;
  while ((m = urlRe.exec(t))) {
    let u = m[0].replace(/[.:!?*]+$/, ''); let host;
    try { host = new URL(u).hostname.toLowerCase(); } catch { continue; }
    if (isBenign(host) || (own && regDomain(host) === own)) continue;
    const ipHost = /^\d+\.\d+\.\d+\.\d+$/.test(host);
    if (ipHost && isPrivateIp(host)) continue;
    if (defanged(u.replace(/^https?:\/\//, '')) || raw.includes('hxxp') || SUSP_EXT.test(u) || ipHost || inZone(m.index)) out.url.add(u.slice(0, 300));
  }
  const domRe = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b/gi;
  while ((m = domRe.exec(t))) {
    const d = m[0].toLowerCase(), tld = m[1].toLowerCase();
    if (!TLDS.has(tld) || isBenign(d) || /^(com|org|net|io|android|ios)\./.test(d)) continue;
    if (own && regDomain(d) === own) continue;
    const prev = t[m.index - 1];
    if (prev === '@') continue;
    if (d.split('.').every(p => /^\d+$/.test(p))) continue;
    if (/\.(js|exe|dll|php|html?|aspx?|json|txt|py|so)$/.test(d) && !defanged(d)) continue;
    if (ok(d, m.index)) out.domain.add(d);
  }
  const mailRe = /\b[a-z0-9._%+-]{2,40}@((?:[a-z0-9-]+\.)+[a-z]{2,10})\b/gi;
  while ((m = mailRe.exec(t))) { const d = m[1].toLowerCase(); if (!isBenign(d) && TLDS.has(d.split('.').pop()) && (defanged(m[0].replace('@', '@')) || inZone(m.index) || raw.includes('[@]'))) out.email.add(m[0].toLowerCase()); }

  const res = {}; let total = 0;
  for (const k of Object.keys(out)) { res[k] = [...out[k]].sort().slice(0, 400); total += res[k].length; }
  return { iocs: res, total, hasDefang: t !== raw };
}
const uniq = a => [...new Set(a)];
const cves = t => uniq((t.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || []).map(x => x.toUpperCase())).slice(0, 40);
const techniques = t => uniq((t.match(/\bT1\d{3}(?:\.\d{3})?\b/g) || [])).slice(0, 80);

/* ----------------------------------------------------------- group attribution */
const groups = readJson(path.join(ROOT, 'collector', 'groups.json'), []);
const aliasMap = new Map();     // normalized alias -> group
const norm = s => s.toLowerCase().replace(/[^a-z0-9]/g, '');
for (const g of groups) for (const a of [g.name, ...g.aliases]) aliasMap.set(norm(a), g);
const escRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// ambiguous everyday words / element names only count when followed by "group", "ransomware", "APT", etc.
const RISKY = new Set('play tick bitter snake cardinal nightclub reaper mercury armageddon monsoon hangover cicada krypton zinc barium thallium iridium strontium holmium europium phosphorus potassium actinium bismuth callisto elfin agenda conti cyclops leviathan lamberts equation buckeye waterbug'.split(' '));
const allAliases = [...new Set(groups.flatMap(g => [g.name, ...g.aliases]))].sort((x, y) => y.length - x.length);
const mk = (list, suffix) => list.length ? new RegExp('(?<![\w-])(' + list.map(escRe).join('|') + ')' + (suffix ? '(?= (?:group|gang|actor|apt|ransomware|threat actor|threat group|hackers?|malware|crew|campaign)\b)' : '(?![\w-])'), 'gi') : /(?!)/g;
const aliasRe = mk(allAliases.filter(a => !RISKY.has(a.toLowerCase())), false);
const riskyRe = mk(allAliases.filter(a => RISKY.has(a.toLowerCase())), true);
const genericRe = /(?<![\w-])(APT ?\d{1,2}|UNC\d{3,5}|TA\d{3,4}|FIN\d{1,2}|Storm-\d{4}|DEV-\d{4}|UAT-?\d{4}|UNK_[A-Za-z]+|TAG-\d{2,3}|CL-(?:STA|CRI|UNK)-\d{4}|(?:[A-Z][a-z]+ )(?:Typhoon|Blizzard|Sandstorm|Sleet|Tempest|Panda|Bear|Kitten|Spider|Chollima|Taurus|Serpens|Ursa|Libra))(?![\w-])/g;

function attribute(title, text) {
  const score = new Map(); // group name -> {g, n}
  const add = (name, g, w) => { const e = score.get(name) || { g, n: 0, inTitle: false }; e.n += w; if (w >= 5) e.inTitle = true; score.set(name, e); };
  for (const [body, w] of [[title, 5], [text, 1]]) {
    let m;
    for (const re of [aliasRe, riskyRe]) { re.lastIndex = 0; while ((m = re.exec(body))) { const g = aliasMap.get(norm(m[1])); if (g) add(g.name, g, w); } }
    genericRe.lastIndex = 0;
    while ((m = genericRe.exec(body))) {
      const g = aliasMap.get(norm(m[1]));
      if (g) add(g.name, g, w); else add(m[1].replace(/^APT(\d)/, 'APT $1').replace(/^APT  /, 'APT '), null, w);
    }
  }
  const res = [];
  for (const [name, e] of score) if (e.inTitle || e.n >= 2) res.push({ name, country: e.g?.country || '??', sponsor: e.g?.sponsor || 'unknown', n: e.n });
  return res.sort((a, b) => b.n - a.n).slice(0, 4);
}
const TAGS = [
  ['ransomware', /ransomware|ransom note|double extortion|encrypts? files/i], ['phishing', /phishing|spear-?phish|credential harvest/i],
  ['zero-day', /zero[- ]day|0-day|exploited in the wild/i], ['supply-chain', /supply[- ]chain|trojanized|poisoned (?:package|update)|npm package|pypi/i],
  ['espionage', /espionage|cyber-?espionage|state-sponsored|nation-state/i], ['botnet', /botnet|\bddos\b/i], ['wiper', /\bwiper\b|destructive malware/i],
  ['backdoor', /backdoor|implant|\brat\b|remote access trojan/i], ['infostealer', /info-?stealer|stealer malware|credential stealer/i], ['ics-ot', /\bICS\b|\bOT\b|SCADA|industrial control|PLC/i],
  ['cloud', /\bAWS\b|\bAzure\b|cloud (?:account|tenant)|Entra|Okta/i], ['mobile', /android|\bios\b|iphone|spyware/i], ['edge-device', /vpn|firewall|fortinet|ivanti|citrix|palo alto|cisco asa|sonicwall|edge device/i],
  ['data-breach', /data breach|leaked data|data leak|exfiltrat/i], ['malvertising', /malvertis|seo poison|fake (?:update|captcha)|clickfix/i], ['ai', /\bLLM\b|artificial intelligence|\bAI[- ]/i],
];
const THREAT_WORDS = /(apt|threat actor|malware|ransomware|campaign|backdoor|phishing|exploit|vulnerabilit|zero-day|botnet|espionage|c2|ioc|attack|breach|advisory|trojan|stealer|ddos)/i;

function score(r) {
  let s = 0;
  if (r.groups.length) s += 25; s += Math.min(30, Math.round(r.iocTotal / 2));
  if (r.tags.includes('zero-day')) s += 15; if (r.cves.length) s += 8; s += Math.min(14, r.techniques.length * 2);
  if (r.tags.includes('espionage') || r.tags.includes('ics-ot')) s += 8;
  return Math.min(100, s);
}

/* ------------------------------------------------------------------- main */
async function main() {
  const t0 = Date.now();
  const sources = readJson(path.join(ROOT, 'collector', 'sources.json'), []);
  const store = FULL ? { reports: [] } : readJson(path.join(DATA, 'reports.json'), { reports: [] });
  const existing = new Map((store.reports || []).map(r => [r.id, r]));
  const cutoff = Date.now() - MAX_AGE_DAYS * 864e5;
  const today = new Date().toISOString().slice(0, 10);

  log(`Fetching ${sources.length} feeds...`);
  const feedRes = await pool(sources, CONCURRENCY, async s => {
    const xml = await get(s.url);
    const items = parseFeed(xml);
    if (!items.length) throw new Error('no items parsed');
    return items;
  });
  const health = [], candidates = [];
  sources.forEach((s, i) => {
    const r = feedRes[i];
    if (!r || r.error) { health.push({ id: s.id, name: s.name, type: s.type, ok: false, error: r?.error || 'unknown', items: 0, new: 0 }); log(`  x ${s.name}: ${r?.error}`); return; }
    let fresh = 0;
    for (const e of r) {
      const d = toDate(e.date) || new Date();
      if (d.getTime() < cutoff) continue;
      const id = sha1(e.link.replace(/[?#].*$/, '').replace(/\/$/, '')).slice(0, 12);
      if (existing.has(id)) continue;
      if (candidates.some(c => c.id === id)) continue;
      candidates.push({ id, src: s, e, published: d.toISOString() }); fresh++;
    }
    health.push({ id: s.id, name: s.name, type: s.type, ok: true, items: r.length, new: fresh });
    log(`  ok ${s.name}: ${r.length} items, ${fresh} new`);
  });

  // Deep fetch article pages where the feed only carried a teaser
  candidates.sort((a, b) => (b.published > a.published ? 1 : -1));
  let deepBudget = MAX_DEEP_FETCH;
  const needDeep = candidates.filter(c => c.src.type !== 'news' || THREAT_WORDS.test(c.e.title)).filter(c => htmlToText(c.e.html).length < 6000);
  const deepSet = new Set(needDeep.slice(0, deepBudget).map(c => c.id));
  log(`Candidates: ${candidates.length}; fetching ${deepSet.size} full articles...`);
  await pool(candidates.filter(c => deepSet.has(c.id)), CONCURRENCY, async c => {
    try { const h = await get(c.e.link, 20000); const txt = articleBody(h); if (txt.length > htmlToText(c.e.html).length) c.fullText = txt; } catch { /* keep teaser */ }
  });

  const newDaily = []; let added = 0;
  for (const c of candidates) {
    const feedText = htmlToText(c.e.html);
    const text = c.fullText || feedText;
    const host = (() => { try { return new URL(c.e.link).hostname; } catch { return ''; } })();
    const { iocs, total, hasDefang } = extractIocs(c.fullText ? c.fullText : text, host);
    const grp = attribute(c.e.title, text);
    const tags = TAGS.filter(([, re]) => re.test(c.e.title + ' ' + text.slice(0, 20000))).map(([n]) => n);
    const rep = {
      id: c.id, title: c.e.title.slice(0, 220), url: c.e.link, source: c.src.name, sourceId: c.src.id, sourceType: c.src.type,
      published: c.published, collected: today, summary: (feedText || text).replace(/\s+/g, ' ').slice(0, 360),
      groups: grp.map(g => ({ name: g.name, country: g.country, sponsor: g.sponsor })), tags,
      cves: cves(text), techniques: techniques(text), iocCounts: Object.fromEntries(Object.entries(iocs).filter(([, v]) => v.length).map(([k, v]) => [k, v.length])),
      iocTotal: total, deep: !!c.fullText, defanged: hasDefang,
    };
    rep.score = score(rep);
    // non-research news that has no threat relevance at all is dropped to keep the feed clean
    if (c.src.type === 'news' && !grp.length && !total && !rep.cves.length && !THREAT_WORDS.test(c.e.title)) continue;
    existing.set(rep.id, rep); added++;
    if (total) {
      const mf = path.join(IOCS, 'by-month', c.published.slice(0, 7) + '.json');
      const month = readJson(mf, { entries: [] }).entries.filter(e => e.report.id !== rep.id);
      month.push({ report: { id: rep.id, title: rep.title, url: rep.url, source: rep.source, published: rep.published, groups: rep.groups.map(g => g.name), cves: rep.cves, techniques: rep.techniques }, iocs });
      writeJson(mf, { entries: month });
      for (const [type, arr] of Object.entries(iocs)) for (const v of arr) newDaily.push({ type, value: v, report: rep.id, groups: rep.groups.map(g => g.name), published: rep.published });
    }
  }
  log(`Added ${added} reports, ${newDaily.length} IoC records.`);

  // retention
  const keepFrom = Date.now() - RETAIN_DAYS * 864e5;
  const reports = [...existing.values()].filter(r => new Date(r.published).getTime() >= keepFrom).sort((a, b) => (a.published < b.published ? 1 : -1)).slice(0, 3000);
  const byId = new Map(reports.map(r => [r.id, r]));

  // aggregate IoCs from the archive folder (source of truth)
  const agg = new Map();
  const walk = d => fs.existsSync(d) ? fs.readdirSync(d, { withFileTypes: true }).flatMap(f => f.isDirectory() ? walk(path.join(d, f.name)) : f.name.endsWith('.json') ? [path.join(d, f.name)] : []) : [];
  for (const f of walk(path.join(IOCS, 'by-month'))) for (const j of readJson(f, { entries: [] }).entries) {
    if (!byId.has(j.report.id)) continue;
    for (const [type, arr] of Object.entries(j.iocs)) for (const v of arr) {
      const k = type + '|' + v; let e = agg.get(k);
      if (!e) agg.set(k, e = { t: type, v, r: [], g: [], first: j.report.published, last: j.report.published });
      if (!e.r.includes(j.report.id)) e.r.push(j.report.id);
      for (const g of j.report.groups) if (!e.g.includes(g)) e.g.push(g);
      if (j.report.published < e.first) e.first = j.report.published; if (j.report.published > e.last) e.last = j.report.published;
    }
  }
  const allIocs = [...agg.values()].sort((a, b) => (a.last < b.last ? 1 : -1));
  const typeTotals = {}; for (const e of allIocs) typeTotals[e.t] = (typeTotals[e.t] || 0) + 1;

  // daily snapshot of what was newly collected today
  if (newDaily.length) {
    const df = path.join(IOCS, 'daily', `${today}.json`);
    const prev = readJson(df, []);
    const seen = new Set(prev.map(x => x.type + '|' + x.value));
    writeJson(df, [...prev, ...newDaily.filter(x => !seen.has(x.type + '|' + x.value))]);
  }

  // outputs: aggregated json/csv + plain-text blocklists per type
  writeJson(path.join(IOCS, 'all.json'), allIocs.map(e => ({ ...e, r: e.r.slice(0, 6) })));
  const csv = ['type,value,first_seen,last_seen,groups,report_count,report_ids'].concat(allIocs.map(e => [e.t, e.v, e.first.slice(0, 10), e.last.slice(0, 10), e.g.join('|'), e.r.length, e.r.join('|')].map(x => `"${String(x).replace(/"/g, '""')}"`).join(','))).join('\n');
  writeText(path.join(IOCS, 'all.csv'), csv + '\n');
  const header = `# ThreatLens IoC feed - generated ${new Date().toISOString()} - source: public vendor reports. Verify before blocking.\n`;
  for (const t of ['ipv4', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email']) writeText(path.join(IOCS, 'feeds', `${t}.txt`), header + allIocs.filter(e => e.t === t).map(e => e.v).join('\n') + '\n');

  // groups
  const gm = new Map();
  for (const g of groups) gm.set(g.name, { name: g.name, country: g.country, sponsor: g.sponsor, aliases: g.aliases, known: true, reports: [], techniques: {}, tags: {}, iocs: 0, last: null, first: null });
  for (const r of reports) for (const g of r.groups) {
    let e = gm.get(g.name);
    if (!e) gm.set(g.name, e = { name: g.name, country: g.country, sponsor: g.sponsor, aliases: [], known: false, reports: [], techniques: {}, tags: {}, iocs: 0, last: null, first: null });
    e.reports.push(r.id); e.iocs += r.iocTotal;
    for (const t of r.techniques) e.techniques[t] = (e.techniques[t] || 0) + 1;
    for (const t of r.tags) e.tags[t] = (e.tags[t] || 0) + 1;
    if (!e.last || r.published > e.last) e.last = r.published; if (!e.first || r.published < e.first) e.first = r.published;
  }
  const groupList = [...gm.values()].filter(g => g.reports.length).map(g => ({
    ...g, reportCount: g.reports.length, reports: g.reports.slice(0, 40),
    techniques: Object.entries(g.techniques).sort((a, b) => b[1] - a[1]).slice(0, 15), tags: Object.entries(g.tags).sort((a, b) => b[1] - a[1]).slice(0, 6),
  })).sort((a, b) => b.reportCount - a.reportCount || (a.last < b.last ? 1 : -1));

  // CISA KEV
  let kev = readJson(path.join(DATA, 'kev.json'), null);
  try {
    const k = JSON.parse(await get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 40000));
    const list = (k.vulnerabilities || []).sort((a, b) => (a.dateAdded < b.dateAdded ? 1 : -1));
    kev = { updated: new Date().toISOString(), total: list.length, catalogVersion: k.catalogVersion, ransomware: list.filter(v => /known/i.test(v.knownRansomwareCampaignUse)).length,
      latest: list.slice(0, 80).map(v => ({ cve: v.cveID, vendor: v.vendorProject, product: v.product, name: v.vulnerabilityName, added: v.dateAdded, due: v.dueDate, ransomware: /known/i.test(v.knownRansomwareCampaignUse), desc: (v.shortDescription || '').slice(0, 280) })) };
    log(`KEV: ${kev.total} entries`);
  } catch (e) { log('KEV fetch failed:', e.message); }
  if (kev) writeJson(path.join(DATA, 'kev.json'), kev);

  // CVE mention leaderboard
  const cveCount = {}; for (const r of reports) for (const c of r.cves) cveCount[c] = (cveCount[c] || 0) + 1;
  const kevSet = new Set((kev?.latest || []).map(v => v.cve));
  const topCves = Object.entries(cveCount).sort((a, b) => b[1] - a[1]).slice(0, 30).map(([cve, n]) => ({ cve, n, kev: kevSet.has(cve) }));

  // stats
  const daily = {}; for (let i = 59; i >= 0; i--) daily[new Date(Date.now() - i * 864e5).toISOString().slice(0, 10)] = { reports: 0, iocs: 0 };
  for (const r of reports) { const d = r.published.slice(0, 10); if (daily[d]) { daily[d].reports++; daily[d].iocs += r.iocTotal; } }
  const tagCount = {}; for (const r of reports) for (const t of r.tags) tagCount[t] = (tagCount[t] || 0) + 1;
  const techCount = {}; for (const r of reports) for (const t of r.techniques) techCount[t.split('.')[0]] = (techCount[t.split('.')[0]] || 0) + 1;
  const countryCount = {}; for (const g of groupList) countryCount[g.country] = (countryCount[g.country] || 0) + g.reportCount;
  const week = Date.now() - 7 * 864e5;
  const meta = {
    updated: new Date().toISOString(), runSeconds: Math.round((Date.now() - t0) / 1000),
    totals: { reports: reports.length, groups: groupList.length, iocs: allIocs.length, cves: Object.keys(cveCount).length, sources: sources.length, sourcesOk: health.filter(h => h.ok).length,
      reports7d: reports.filter(r => new Date(r.published).getTime() > week).length, newThisRun: added, iocsThisRun: newDaily.length },
    iocTypes: typeTotals, daily, tags: tagCount, techniques: Object.entries(techCount).sort((a, b) => b[1] - a[1]).slice(0, 25), countries: countryCount, topCves, sources: health,
  };
  writeJson(path.join(DATA, 'meta.json'), meta);
  writeJson(path.join(DATA, 'groups.json'), groupList);
  writeJson(path.join(DATA, 'reports.json'), { updated: meta.updated, reports });
  log(`Done in ${meta.runSeconds}s: ${reports.length} reports, ${groupList.length} groups, ${allIocs.length} unique IoCs.`);
}
main().catch(e => { console.error('Collector failed:', e); process.exit(0); /* never break the Netlify build */ });
