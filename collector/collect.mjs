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
const RETAIN_DAYS = +process.env.RETAIN_DAYS || 240;     // keep reports this long
const MAX_DEEP_FETCH = +process.env.MAX_DEEP_FETCH || 450; // article pages fetched per run
const SCHEMA = 2;
const MAX_BYTES = 3_000_000;   // never read more than 3 MB of one response
const MAX_TEXT = 400_000;      // never analyse more than 400k characters of one article                                         // bump to force old reports to be re-tagged
const CONCURRENCY = 10;
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 ThreatLens/2.0';
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
// only public http(s) addresses; no localhost / private ranges
function isSafeUrl(u) {
  try { const x = new URL(u); if (!/^https?:$/.test(x.protocol) || x.username || x.password) return false; const h = x.hostname.toLowerCase();
    return !(h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal') || /^(127\.|10\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h) || h === '[::1]'); } catch { return false; }
}
// read a response with a hard size cap and decode it with the right charset (UTF-8, windows-1254 Turkish, windows-1256 Persian ...)
async function readCapped(r, max) {
  const chunks = []; let n = 0;
  if (r.body && r.body.getReader) {
    const reader = r.body.getReader();
    for (;;) { const { done, value } = await reader.read(); if (done) break; chunks.push(Buffer.from(value)); n += value.length; if (n > max) { reader.cancel().catch(() => {}); break; } }
  } else chunks.push(Buffer.from(await r.arrayBuffer()));
  const buf = Buffer.concat(chunks).subarray(0, max);
  let cs = ((r.headers.get('content-type') || '').match(/charset=["']?([\w-]+)/i) || [])[1];
  if (!cs) cs = (buf.subarray(0, 300).toString('latin1').match(/<\?xml[^>]*encoding=["']([\w-]+)/i) || buf.subarray(0, 2000).toString('latin1').match(/<meta[^>]+charset=["']?([\w-]+)/i) || [])[1];
  try { return new TextDecoder(cs || 'utf-8').decode(buf); } catch { return buf.toString('utf8'); }
}
async function get(url, timeout = 25000, retries = 1) {
  if (!isSafeUrl(url)) throw new Error('blocked url');
  for (let a = 0; ; a++) {
    try {
      const r = await fetch(url, { headers: { 'User-Agent': UA, 'Accept-Language': 'en-US,en;q=0.9', Accept: 'text/html,application/xml,application/rss+xml,application/json,*/*' }, redirect: 'follow', signal: AbortSignal.timeout(timeout) });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return await readCapped(r, MAX_BYTES);
    } catch (e) { if (a >= retries || /HTTP (403|404|410)/.test(e.message)) throw e; await new Promise(r => setTimeout(r, 1500)); }
  }
}
const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ndash: '-', mdash: '-', hellip: '...', rsquo: "'", lsquo: "'", ldquo: '"', rdquo: '"' };
const decode = s => s.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (m, e) => {
  if (e[0] === '#') { const c = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); try { return String.fromCodePoint(c); } catch { return ' '; } }
  return ENT[e.toLowerCase()] ?? m;
});
function htmlToText(h) {
  return decode(h
    .replace(/<(script|style|noscript|svg|nav|footer|header|form)[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<\/t[dh]>/gi, ' | ')
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
// zone abbreviations JavaScript does not understand -> numeric offsets
const TZ = { CEST: '+0200', CET: '+0100', BST: '+0100', MSK: '+0300', IRST: '+0330', IRDT: '+0430', TRT: '+0300', EEST: '+0300', EET: '+0200', AEST: '+1000', AEDT: '+1100', JST: '+0900', KST: '+0900', HKT: '+0800', SGT: '+0800', PKT: '+0500', SAST: '+0200', WIB: '+0700', NZST: '+1200', NZDT: '+1300', IDT: '+0300' };
const toDate = s => {
  if (!s) return null;
  s = String(s).trim().replace(/\b(CEST|CET|BST|MSK|IRST|IRDT|TRT|EEST|EET|AEST|AEDT|JST|KST|HKT|SGT|PKT|SAST|WIB|NZST|NZDT|IDT)\b/, (_, z) => TZ[z]);
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) s = s.replace(' ', 'T') + 'Z';   // no zone given: UTC, never the machine's local time
  const d = new Date(s); return isNaN(d) ? null : d;
};
// some feeds carry only a date (or a fake 00:00:00): the time of day is unknown and must not be shown as if it were real
const isDateOnlyRaw = s => { s = String(s || '').trim(); return !!s && (!/\d{1,2}:\d{2}/.test(s) || /(?:^|[ T])00:00(?::00)?(?:\.0+)?\s*(?:Z|GMT|UTC|[+-]\d{2}:?\d{2})?$/.test(s)); };

/* ------------------------------------------------------------ IoC extraction */
const BENIGN = new Set(`anthropic.com claude.ai openai.com chatgpt.com langchain.com huggingface.co powerbi.com atlassian.net atlassian.com notion.so figma.com stackoverflow.com google.com googleapis.com gstatic.com youtube.com youtu.be microsoft.com windows.com windowsupdate.com live.com office.com office365.com outlook.com azure.com azureedge.net msn.com bing.com github.com githubusercontent.com gitlab.com bitbucket.org twitter.com x.com t.co facebook.com linkedin.com instagram.com reddit.com medium.com wordpress.com wikipedia.org mozilla.org apple.com icloud.com amazon.com amazonaws.com cloudfront.net cloudflare.com akamai.net akamaihd.net fastly.net adobe.com oracle.com java.com python.org nodejs.org npmjs.com pypi.org virustotal.com hybrid-analysis.com any.run joesandbox.com urlscan.io shodan.io censys.io mitre.org attack.mitre.org nist.gov nvd.nist.gov cve.org cisa.gov fbi.gov ic3.gov ncsc.gov.uk us-cert.gov europa.eu paloaltonetworks.com talosintelligence.com cisco.com kaspersky.com securelist.com eset.com welivesecurity.com sophos.com symantec.com broadcom.com trendmicro.com checkpoint.com crowdstrike.com mandiant.com sentinelone.com fortinet.com malwarebytes.com recordedfuture.com proofpoint.com volexity.com elastic.co bitdefender.com avast.com mcafee.com zscaler.com huntress.com sekoia.io thedfirreport.com bleepingcomputer.com thehackernews.com krebsonsecurity.com securityweek.com darkreading.com therecord.media wired.com reuters.com bbc.com bbc.co.uk nytimes.com washingtonpost.com theregister.com arstechnica.com zdnet.com vice.com vimeo.com slack.com zoom.us dropbox.com box.com sharepoint.com onedrive.com drive.google.com docs.google.com t.me telegram.org discord.com discord.gg pastebin.com bit.ly goo.gl tinyurl.com ow.ly feedburner.com w3.org example.com example.org example.net localhost schema.org gravatar.com wp.com cdn.jsdelivr.net jsdelivr.net unpkg.com cloudflare-dns.com dns.google opendns.com quad9.net archive.org web.archive.org virusbulletin.com blogspot.com tumblr.com substack.com gmail.com yahoo.com hotmail.com protonmail.com proton.me mail.com`.split(/\s+/));
const TLDS = new Set(`com net org io info biz xyz top online site club live shop store tech app dev cloud pro icu vip cn ru ir kp kr jp in de fr uk us co me tv cc ws to su ua by kz tk ml ga cf gq pw link click work page space website fun one ink cyou buzz sbs bond rest cam monster today life world network systems services solutions digital email support center agency news media group company ltd inc tel mobi name eu nl se no fi dk pl cz ro bg hu gr tr il sa ae eg pk bd vn th id my sg ph hk tw au nz br ar mx cl pe za ng ke ma tn dz ly sy iq lb jo af cu ve it es pt at ch be ie lt lv ee rs hr si sk md am az ge kg uz tj tm mn la kh mm np lk bt ir cx gg im je sx gl nu st sh ac io vc bz tc ms ag gd lc dm kn xn`.split(/\s+/));
const SUSP_EXT = /\.(exe|dll|zip|rar|7z|ps1|sh|js|hta|bat|vbs|bin|msi|iso|lnk|doc|docx|xls|xlsx|jar|scr|elf|apk|php)(\?|$)/i;
const EXCLUDE_IP = new Set(['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '0.0.0.0', '255.255.255.255', '208.67.222.222', '208.67.220.220']);
const ZONE_RE = /(indicators?(?: of compromise)?|\bIOCs?\b|\bIoCs\b|\bIOAs?\b|network indicators|host indicators|file (?:hashes|indicators)|\bhashes\b|observed (?:ips?|domains?|urls?|infrastructure|ip addresses)|malicious (?:domains?|ips?|urls?|infrastructure|files?|ip addresses)|\bC2s?\b|\bC&C\b|command[- ]and[- ]control|ip addresses?|appendix|threat actor infrastructure|infrastructure)/gi;
const CTX_RE = /\b(ip|address|c2|c&c|server|host|domain|connect|beacon|download|payload|infrastructure|resolve|contact|communicat|exfil|callback|staging|hosted|observed|malicious|scann|attack|exploit)/i;
const FILE_BENIGN = new Set('cmd.exe powershell.exe pwsh.exe svchost.exe rundll32.exe regsvr32.exe mshta.exe cscript.exe wscript.exe explorer.exe notepad.exe calc.exe conhost.exe lsass.exe services.exe winlogon.exe csrss.exe wininit.exe taskhost.exe taskhostw.exe msiexec.exe schtasks.exe certutil.exe bitsadmin.exe wmic.exe net.exe net1.exe ping.exe whoami.exe tasklist.exe taskkill.exe reg.exe sc.exe at.exe kernel32.dll ntdll.dll user32.dll advapi32.dll shell32.dll ws2_32.dll wininet.dll winhttp.dll crypt32.dll setup.exe install.exe update.exe'.split(' '));
const MONTHS = 'jan feb mar apr may jun jul aug sep oct nov dec'.split(' ');
const DATE_RE = /(\d{1,2}\/\d{1,2}\/\d{4}|\d{4}-\d{2}-\d{2}|\d{4}\/\d{2}\/\d{2}|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.? \d{1,2},? \d{4}|\d{1,2} (?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]* \d{4})/i;
function parseObsDate(s) {
  let m;
  if ((m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/))) { let a = +m[1], b = +m[2]; const y = +m[3]; let mo = a, d = b; if (a > 12) { mo = b; d = a; } return mo >= 1 && mo <= 12 && d >= 1 && d <= 31 ? `${y}-${String(mo).padStart(2, '0')}-${String(d).padStart(2, '0')}` : null; }
  if ((m = s.match(/^(\d{4})[-/](\d{2})[-/](\d{2})$/))) return `${m[1]}-${m[2]}-${m[3]}`;
  if ((m = s.match(/^([a-z]{3})[a-z]*\.? (\d{1,2}),? (\d{4})$/i))) { const mo = MONTHS.indexOf(m[1].toLowerCase()) + 1; return mo ? `${m[3]}-${String(mo).padStart(2, '0')}-${String(+m[2]).padStart(2, '0')}` : null; }
  if ((m = s.match(/^(\d{1,2}) ([a-z]{3})[a-z]* (\d{4})$/i))) { const mo = MONTHS.indexOf(m[2].toLowerCase()) + 1; return mo ? `${m[3]}-${String(mo).padStart(2, '0')}-${String(+m[1]).padStart(2, '0')}` : null; }
  return null;
}
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
const validIpv6 = s => {
  if (!/^[0-9a-f:]+$/i.test(s) || s.length < 6) return false;
  const dbl = s.includes('::'); if ((s.match(/::/g) || []).length > 1 || /:::/.test(s)) return false;
  const groups = s.split(':').filter(Boolean);
  if (groups.some(g => g.length > 4)) return false;
  if (!dbl && groups.length !== 8) return false;
  if (dbl && groups.length > 7) return false;
  const lo = s.toLowerCase();
  if (lo === '::' || lo === '::1' || /^f[cde][0-9a-f]{2}:/.test(lo) || /^fe[89ab][0-9a-f]:/.test(lo) || /^2001:0?db8:/.test(lo) || /^ff[0-9a-f]{2}:/.test(lo)) return false;
  return true;
};

/**
 * Extract indicators of compromise from article text.
 * Accepts an indicator when it is defanged, sits in/after an "IOCs / indicators / hashes / C2" heading,
 * has C2/server/IP wording nearby, or belongs to a list (several indicators of the same kind close together -
 * e.g. an IP table). Observed dates written next to an indicator ("103.1.2.3 | 10/17/2026") are captured.
 */
function extractIocs(raw, ownHost) {
  const t = refang(raw);
  const zones = []; let zm;
  ZONE_RE.lastIndex = 0;
  while ((zm = ZONE_RE.exec(t))) zones.push([zm.index, zm.index + 6000]);
  const inZone = i => zones.some(([a, b]) => i >= a && i <= b);
  const defanged = v => { const dv = v.replace(/\./g, '[.]'); return raw.includes(dv) || raw.includes(v.replace(/\./g, '(.)')) || raw.includes(v.replace(/\./g, '[dot]')) || raw.includes(v.replace(/^https?/, 'hxxp').replace(/\./g, '[.]')); };
  const ctx = (v, i, w = 90) => CTX_RE.test(t.slice(Math.max(0, i - w), i + v.length + w));
  const own = ownHost ? regDomain(ownHost) : '';
  const out = { ipv4: new Set(), ipv6: new Set(), domain: new Set(), url: new Set(), md5: new Set(), sha1: new Set(), sha256: new Set(), sha512: new Set(), email: new Set(), wallet: new Set(), file: new Set() };
  const obs = {};
  let m;

  // observed date next to an indicator: same line after it, or a lone date on the next non-empty line
  const obsAfter = (v, i) => {
    let e = t.indexOf('\n', i); if (e < 0) e = t.length;
    const same = t.slice(i + v.length, Math.min(e, i + v.length + 160)).match(DATE_RE);
    if (same) return parseObsDate(same[1].trim());
    const nxt = t.slice(i + v.length, i + v.length + 120).replace(/^[\s|:,;-]+/, '');   // next cell / next line
    const mm = nxt.match(DATE_RE); if (mm && mm.index === 0) return parseObsDate(mm[1].trim());
    return null;
  };
  const clustered = (list, k, win) => {                         // is there a list of >= k same-kind candidates around each item?
    const idx = list.map(x => x.i).sort((a, b) => a - b), good = new Set();
    for (let a = 0; a < idx.length; a++) { let n = 1; for (let b = a - 1; b >= 0 && idx[a] - idx[b] <= win; b--) n++; for (let b = a + 1; b < idx.length && idx[b] - idx[a] <= win; b++) n++; if (n >= k) good.add(idx[a]); }
    return good;
  };
  const add = (type, v, i) => { out[type].add(v); const d = obsAfter(v, i); if (d) obs[type + '|' + v] = d; };

  // hashes: unambiguous, accepted anywhere
  const hashRe = /\b[a-fA-F0-9]{32,128}\b/g;
  while ((m = hashRe.exec(t))) {
    const h = m[0].toLowerCase(); const L = h.length;
    if (L !== 32 && L !== 40 && L !== 64 && L !== 128) continue;
    if (!/[0-9]/.test(h) || !/[a-f]/.test(h) || /^(.)\1+$/.test(h)) continue;
    add(L === 32 ? 'md5' : L === 40 ? 'sha1' : L === 64 ? 'sha256' : 'sha512', h, m.index);
  }

  // IPv4
  const ipCands = [], ipRe = /(?<![\w.\/-])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w-]|\.\d)/g;
  while ((m = ipRe.exec(t))) { const ip = m[0]; if (EXCLUDE_IP.has(ip) || isPrivateIp(ip)) continue; if (/\.0$/.test(ip) && !defanged(ip)) continue; if (/(?:version|ver\.?|\bv|build|release|update|upgrade|patch)\s*$/i.test(t.slice(Math.max(0, m.index - 14), m.index)) && !defanged(ip) && !inZone(m.index)) continue; ipCands.push({ v: ip, i: m.index }); }
  const ipList = clustered(ipCands, 3, 400);
  for (const c of ipCands) if (defanged(c.v) || inZone(c.i) || ctx(c.v, c.i) || ipList.has(c.i)) add('ipv4', c.v, c.i);

  // IPv6
  const v6Re = /(?<![\w:])(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}(?::[0-9a-f]{1,4})*(?![\w:])|(?<![\w:])::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}(?![\w:])/gi;
  while ((m = v6Re.exec(t))) { const a = m[0]; if (validIpv6(a) && (defanged(a) || inZone(m.index) || ctx(a, m.index))) add('ipv6', a.toLowerCase(), m.index); }

  // URLs
  const urlCands = [], urlRe = /\bhttps?:\/\/[^\s"'<>()\[\]{},;|\\`]+/gi;
  while ((m = urlRe.exec(t))) {
    let u = m[0].replace(/[.:!?*…]+$/, ''); let host;
    try { host = new URL(u).hostname.toLowerCase(); } catch { continue; }
    if (isBenign(host) || (own && regDomain(host) === own)) continue;
    const ipHost = /^\d+\.\d+\.\d+\.\d+$/.test(host);
    if (!ipHost && (!host.includes('.') || !TLDS.has(host.split('.').pop()))) continue;
    if (ipHost && isPrivateIp(host)) continue;
    urlCands.push({ v: u.slice(0, 300), i: m.index, ipHost });
  }
  const urlList = clustered(urlCands, 3, 600);
  for (const c of urlCands) if (defanged(c.v.replace(/^https?:\/\//, '')) || raw.includes('hxxp') || SUSP_EXT.test(c.v) || c.ipHost || inZone(c.i) || urlList.has(c.i)) add('url', c.v, c.i);

  // domains
  const domCands = [], domRe = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b/gi;
  while ((m = domRe.exec(t))) {
    const d = m[0].toLowerCase(), tld = m[1].toLowerCase();
    if (!TLDS.has(tld) || isBenign(d) || /^(com|org|net|io|android|ios)\./.test(d)) continue;
    if (own && regDomain(d) === own) continue;
    if (t[m.index - 1] === '@') continue;
    if (d.split('.').every(p => /^\d+$/.test(p))) continue;
    if (/\.(js|exe|dll|php|html?|aspx?|json|txt|py|so)$/.test(d) && !defanged(d)) continue;
    domCands.push({ v: d, i: m.index });
  }
  const domList = clustered(domCands, 4, 500);
  for (const c of domCands) if (defanged(c.v) || inZone(c.i) || ctx(c.v, c.i) || domList.has(c.i)) add('domain', c.v, c.i);

  // e-mail
  const mailRe = /\b[a-z0-9._%+-]{2,40}@((?:[a-z0-9-]+\.)+[a-z]{2,10})\b/gi;
  while ((m = mailRe.exec(t))) { const d = m[1].toLowerCase(); if (!isBenign(d) && TLDS.has(d.split('.').pop()) && (defanged(m[0]) || inZone(m.index) || raw.includes('[@]'))) out.email.add(m[0].toLowerCase()); }

  // crypto wallets (ransom notes, payment addresses)
  const walRe = /\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b/g;
  while ((m = walRe.exec(t))) { if (/wallet|bitcoin|btc|ethereum|\beth\b|monero|payment address|ransom|donat|crypto/i.test(t.slice(Math.max(0, m.index - 140), m.index + 140)) || inZone(m.index)) out.wallet.add(m[0]); }

  // malicious-looking file names, only inside an IoC section
  const fileRe = /(?<![\w.\\\/-])[A-Za-z0-9_][\w.-]{0,60}\.(?:exe|dll|ps1|bat|vbs|hta|lnk|msi|scr|iso|jar|apk|docm|xlsm|xll|wsf|cpl|sys|elf)\b/gi;
  while ((m = fileRe.exec(t))) { const f = m[0]; if (!FILE_BENIGN.has(f.toLowerCase()) && inZone(m.index) && f.length > 5) out.file.add(f); }

  const res = {}; let total = 0;
  for (const k of Object.keys(out)) { res[k] = [...out[k]].sort().slice(0, 500); total += res[k].length; }
  const keepObs = {}; for (const [k, v] of Object.entries(obs)) { const [ty, ...rest] = k.split('|'); if (res[ty]?.includes(rest.join('|'))) keepObs[k] = v; }
  return { iocs: res, obs: keepObs, total, hasDefang: t !== raw };
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
// STRONG terms prove a text is about threats on their own; WEAK terms (leak, scam, incident...) need to appear twice or in the title
const STRONG_RE = /(\bapt ?\d*\b|threat actor|threat group|malware|ransomware|backdoor|phish|exploit|vulnerabilit|zero-?day|botnet|espionage|\bc2\b|\bc&c\b|\bioc|attack|breach|trojan|stealer|ddos|\bhack|cyber|rootkit|spyware|\brce\b|\bcve-\d|wiper|extortion|exfiltrat|vishing|smishing|infostealer|атак|эксплойт|эксплуат|уязвим|вредонос|малвар|бэкдор|руткит|троян|шифроваль|вымогател|фишинг|ботнет|ддос|кибер|хакер|взлом)/i;
const WEAK_RE = /(campaign|advisory|malicious|compromis|supply[- ]chain|leak|scam|fraud|payload|loader|incident|credential|утечк|угроз|стилер|дроппер)/ig;
const THREAT_WORDS = STRONG_RE;   // (kept for older call sites)
// is this text about threats / security incidents at all? (English, Russian, Turkish, Azerbaijani, Persian, Arabic, Hebrew)
const isThreatText = (t, title = '') => STRONG_RE.test(t) || (t.match(WEAK_RE) || []).length >= 2 || (title && new RegExp(WEAK_RE.source, 'i').test(title)) || CYBER.test(t) || localCyber(t);

function score(r) {
  let s = 0;
  if (r.groups.length) s += 25; s += Math.min(30, Math.round(r.iocTotal / 2));
  if (r.tags.includes('zero-day')) s += 15; if (r.cves.length) s += 8; s += Math.min(14, r.techniques.length * 2);
  if (r.tags.includes('espionage') || r.tags.includes('ics-ot')) s += 8;
  return Math.min(100, s);
}

/* ----------------------------------------------------------- country tagging */
// Each country has aliases (English, Russian stems, capitals, demonyms). A trailing "~" = any word ending
// (Russian declension), a leading "=" = case-sensitive match. Mentioned in title / intro / several times => tagged.
const countryList = readJson(path.join(ROOT, 'collector', 'countries.json'), []);
const LET = '[\\p{L}\\p{N}_]';
const aliasPattern = a => (a.startsWith('^') ? '[ובלהמכשوبلفكس]{0,2}' : '') + escRe(a.replace(/^[=^]/, '')).replace(/~/g, '\\p{L}{0,6}');
const countryRes = countryList.map(c => {
  const ci = c.aliases.filter(a => !a.startsWith('=')), cs = c.aliases.filter(a => a.startsWith('='));
  const mk = (list, fl) => list.length ? new RegExp('(?<!' + LET + ')(?:' + list.sort((x, y) => y.length - x.length).map(a => aliasPattern(normHe(normAr(a)))).join('|') + ')(?!' + LET + ')', fl) : null;
  return { code: c.code, ci: mk(ci, 'giu'), cs: mk(cs, 'gu'), avoid: c.avoidIf ? new RegExp(c.avoidIf, 'i') : null };
});
const count = (re, t) => { if (!re || !t) return 0; re.lastIndex = 0; let n = 0; while (re.exec(t)) n++; return n; };
function detectCountries(title, text, srcCountry) {
  const nt = normHe(normAr(title)), nx = normHe(normAr(text)), intro = nx.slice(0, 1500), res = [];
  for (const c of countryRes) {
    const bad = c.avoid && c.avoid.test(title + ' ' + text);
    const f = t => count(c.ci, t) + (bad ? 0 : count(c.cs, t));
    let sc = f(nt) * 5 + f(intro) * 2 + f(nx.slice(1500));
    if (srcCountry === c.code) sc += 3;
    if (sc >= 1) res.push([c.code, sc]);
  }
  return res.sort((a, b) => b[1] - a[1]).slice(0, 10).map(x => x[0]);
}
// strict "is this about cyber security?" test for general-news (regional) feeds: specific terms only
// (no bare "exploit", "surveillance", "vulnerable", "breach", "Pegasus" the airline, "Cybercab", "Cyberpunk")
const CYBER = /(cyber(?!cab|truck|punk)|\bhack(?:er|ers|ed|ing|s)?\b|malware|ransomware|phish|spyware|pegasus spyware|data (?:leak|breach)|\bddos\b|botnet|zero-?day|vulnerabilit|\bCVE-\d|\bAPT ?\d{1,2}\b|\bUNC\d{3,}|infostealer|backdoor|кибер|хакер|вредонос|утечк\S* (?:данных|информации|персональных|баз)|фишинг|уязвимост|вымогател|siber)/i;

/* ------------------------------------------------- multilingual keywords (Turkish / Azerbaijani / Persian / Russian) */
// Local-language articles keep their original title; matching glossary terms add English keywords ("en") that the
// site searches, so "ransomware" finds "fidye yazılımı", "fidyə proqramı" and "باج‌افزار".
const glossary = readJson(path.join(ROOT, 'collector', 'glossary.json'), {});
const compileGl = (list, norm = x => x, isLatinList = false) => (list || []).map(g => { try { return { re: new RegExp(norm(isLatinList ? '(?<![a-z0-9])(?:' + g.p + ')' : g.p), 'iu'), en: g.en, tag: g.tag || '', weak: !!g.weak }; } catch { return null; } }).filter(Boolean);
// one normaliser for Arabic-script text (Arabic + Persian): diacritics, tatweel, ZWNJ, alef / yeh / kaf / teh-marbuta variants
function normAr(t) { return t.replace(/[\u200c\u200e\u200f\u064B-\u065F\u0640\u0670]/g, '').replace(/[يىئ]/g, 'ی').replace(/ك/g, 'ک').replace(/ة/g, 'ه').replace(/[أإآٱ]/g, 'ا').replace(/ؤ/g, 'و').replace(/ە/g, 'ه'); }
// Hebrew: strip niqqud, fold final letters
function normHe(t) { return t.replace(/[\u0591-\u05C7]/g, '').replace(/ך/g, 'כ').replace(/ם/g, 'מ').replace(/ן/g, 'נ').replace(/ף/g, 'פ').replace(/ץ/g, 'צ'); }
const GL = { latin: compileGl(glossary.latin, x => x, true), fa: compileGl(glossary.fa, normAr), ar: compileGl(glossary.ar, normAr), he: compileGl(glossary.he, normHe), ru: compileGl(glossary.ru) };
const foldLatin = t => t.replace(/İ/g, 'i').toLowerCase().replace(/ı/g, 'i').replace(/ş/g, 's').replace(/ğ/g, 'g').replace(/ç/g, 'c').replace(/ö/g, 'o').replace(/ü/g, 'u').replace(/ə/g, 'e').replace(/[âàá]/g, 'a').replace(/[îíì]/g, 'i').replace(/[ûúù]/g, 'u');
const normFa = t => t.replace(/[‌‎‏]/g, '').replace(/ي/g, 'ی').replace(/ك/g, 'ک').replace(/ە/g, 'ه').replace(/[ً-ٟـ]/g, '');
const normRu = t => t.toLowerCase().replace(/ё/g, 'е');
function glossHits(text) {
  const t = text.slice(0, 6000), out = [], seen = new Set();
  const ar = normAr(t), forms = [[GL.latin, foldLatin(t)], [GL.fa, ar], [GL.ar, ar], [GL.he, normHe(t)], [GL.ru, normRu(t)]];
  for (const [list, s] of forms) for (const g of list) if (!seen.has(g.en) && g.re.test(s)) { seen.add(g.en); out.push(g); }
  return out;
}
// is this local-language text about cyber security? one specific term, or two weak ones, is enough
function localCyber(text) { const h = glossHits(text); return h.some(g => !g.weak) || h.length >= 2; }
function detectLang(t) {
  const s = t.slice(0, 800), letters = (s.match(/\p{L}/gu) || []).length || 1;
  if ((s.match(/[\u0590-\u05FF]/g) || []).length / letters > 0.3) return 'he';
  if ((s.match(/[؀-ۿ]/g) || []).length / letters > 0.3) return (/[پچژگ]/.test(s) || (s.match(/[کی]/g) || []).length > (s.match(/[كي]/g) || []).length) ? 'fa' : 'ar';
  if ((s.match(/[Ѐ-ӿ]/g) || []).length / letters > 0.3) return 'ru';
  if (/[əƏ]/.test(s)) return 'az';
  if ((s.match(/[ıİğĞşŞ]/g) || []).length >= 2) return 'tr';
  if ((foldLatin(s).match(/\b(ve|bir|bu|icin|ile|daha|olarak|gibi|ancak|veya|hakkinda)\b/g) || []).length >= 3) return 'tr';
  return 'en';
}

/* ------------------------------------------------------- duplicate coverage -> "stories" */
// Several outlets report the same event. Reports from the last 21 days whose titles share rare words (TF-IDF),
// CVE ids or the same threat actor are grouped; every member gets the same `story` id.
const STOP = new Set('the and for with from that this have has are was were will its into over after about more than amid says said new how why what who when your you our their they them been being can could would should may might not but all any out via vs per one two three use used using based hackers attack attacks cyber security'.split(' '));
function clusterStories(reports, days = 21) {
  const now = Date.now();
  const items = reports.filter(r => now - new Date(r.published).getTime() < days * 864e5).sort((a, b) => (a.published < b.published ? -1 : 1));
  const words = r => { const s = new Set(); for (const w of (r.title.toLowerCase().match(/[\p{L}\p{N}][\p{L}\p{N}-]*/gu) || [])) if (w.length >= 4 && !STOP.has(w) && !/^\d+$/.test(w)) s.add(w); return s; };
  // "named" tokens contain a digit, CamelCase or ALL-CAPS (PHP2Shell, MadPot, NGINX): strong evidence of the same story
  const named = r => { const s = new Set(); for (const w of (r.title.match(/[\p{L}\p{N}][\p{L}\p{N}-]*/gu) || [])) if ((/\d/.test(w) && !/^\d+$/.test(w)) || /[a-z][A-Z]/.test(w) || /^[A-Z0-9]{4,}$/.test(w)) s.add(w.toLowerCase()); return s; };
  // CVE ids / actors only count when the report is focused on them (a long advisory listing 40 CVEs links nothing)
  const keys = r => new Set([...((r.cves || []).length <= 3 ? r.cves : []), ...((r.groups || []).length <= 2 ? r.groups.map(g => 'g:' + g.name.toLowerCase()) : [])]);
  const T = items.map(words), NM = items.map(named), K = items.map(keys);
  const df = new Map(); for (const s of T) for (const w of s) df.set(w, (df.get(w) || 0) + 1);
  const N = items.length, maxDf = Math.max(10, Math.floor(N * 0.015)), idf = w => Math.log((N + 1) / (df.get(w) || 1));
  for (const s of T) for (const w of [...s]) if (df.get(w) > maxDf) s.delete(w);
  const norm = T.map(s => Math.sqrt([...s].reduce((a, w) => a + idf(w) ** 2, 0)) || 1);
  const inv = new Map(), push = (k, i) => { if (!inv.has(k)) inv.set(k, []); inv.get(k).push(i); };
  T.forEach((s, i) => { for (const w of s) if (df.get(w) <= maxDf) push(w, i); });
  K.forEach((s, i) => { for (const k of s) push(k, i); });
  // how strongly are two reports the same story? 0 = not linked
  const link = (a, b) => {
    let dot = 0, rare = 0, nm = 0;
    for (const w of T[a]) if (T[b].has(w)) { dot += idf(w) ** 2; if (w.length >= 7 && (df.get(w) || 99) <= 12) rare++; }
    for (const w of NM[a]) if (NM[b].has(w) && (df.get(w) || 99) <= 25) nm++;
    const cos = dot / (norm[a] * norm[b]);
    const cve = [...K[a]].some(k => !k.startsWith('g:') && K[b].has(k)), grp = [...K[a]].some(k => k.startsWith('g:') && K[b].has(k));
    return (cos >= 0.45 || (cve && cos >= 0.1) || (nm >= 1 && cos >= 0.15) || (rare >= 2 && cos >= 0.12) || (grp && cos >= 0.35)) ? cos + 0.01 : 0;
  };
  const cid = items.map(() => -1), clusters = [];
  for (let i = 0; i < items.length; i++) {                 // oldest first: each report joins the best earlier story or starts its own
    const cand = new Set();
    for (const k of [...T[i], ...K[i]]) for (const j of inv.get(k) || []) if (j < i && inv.get(k).length <= 80) cand.add(j);
    // a report joins a story only if it matches the story's first report, or at least two of its members (stops topic drift)
    const per = new Map();
    for (const j of cand) {
      const c = clusters[cid[j]];
      if (items[i].sourceId === items[j].sourceId) continue;
      if (c.members.length >= 40 || new Date(items[i].published) - new Date(items[c.members[0]].published) > 5 * 864e5) continue;
      const sc = link(i, j); if (!sc) continue;
      const e = per.get(cid[j]) || { n: 0, best: 0, lead: false };
      e.n++; e.best = Math.max(e.best, sc); if (j === c.members[0]) e.lead = true; per.set(cid[j], e);
    }
    const ok = [...per.entries()].filter(([, e]) => e.lead || e.n >= 2).sort((x, y) => y[1].best - x[1].best)[0];
    const best = ok ? ok[0] : -1;
    if (best >= 0) { cid[i] = best; clusters[best].members.push(i); } else { cid[i] = clusters.length; clusters.push({ members: [i] }); }
  }
  let stories = 0;
  for (const c of clusters) {
    if (c.members.length < 2) { delete items[c.members[0]].story; continue; }
    const id = 's' + items[c.members[0]].id.slice(0, 8); stories++;
    for (const m of c.members) items[m].story = id;
  }
  return stories;
}

/* -------------------------------------------------------------- CVE scores: EPSS + CVSS (free, no API key) */
// EPSS (FIRST.org): probability that a CVE is exploited in the next 30 days - refreshed daily, 90 CVEs per request.
// CVSS: base score from the CVE record (MITRE CVE Services, includes CISA-ADP scores) - fetched once and cached.
async function enrichCves(ids, kevAll) {
  const file = path.join(DATA, 'cves.json');
  const db = readJson(file, { c: {} }).c || {};
  const day = new Date().toISOString().slice(0, 10);
  const needE = ids.filter(id => !db[id] || db[id].d !== day), batches = [];
  for (let i = 0; i < needE.length; i += 90) batches.push(needE.slice(i, i + 90));
  await pool(batches, 4, async b => {
    try {
      const j = JSON.parse(await get('https://api.first.org/data/v1/epss?limit=100&cve=' + b.join(','), 30000));
      const got = new Map((j.data || []).map(x => [String(x.cve).toUpperCase(), x]));
      for (const id of b) { const x = got.get(id); db[id] = { ...(db[id] || {}), e: x ? +(+x.epss).toFixed(5) : null, p: x ? +(+x.percentile).toFixed(4) : null, d: day }; }
    } catch { /* keep yesterday's values */ }
  });
  const MAXS = +process.env.CVSS_PER_RUN || 150;
  const needS = ids.filter(id => (db[id]?.s === undefined || db[id]?.s === null) && (db[id]?.ct || 0) < 6).slice(0, MAXS);
  await pool(needS, 6, async id => {
    const e = db[id] = db[id] || {};
    try {
      const j = JSON.parse(await get('https://cveawg.mitre.org/api/cve/' + id, 15000, 0));
      const cna = j.containers?.cna?.metrics || [], adp = (j.containers?.adp || []).flatMap(a => a.metrics || []);
      const pick = ms => ms.map(m => m.cvssV3_1 || m.cvssV3_0).find(Boolean);
      const best = pick(cna) || pick(adp) || cna.map(m => m.cvssV4_0).find(Boolean) || adp.map(m => m.cvssV4_0).find(Boolean);
      if (best && typeof best.baseScore === 'number') { e.s = best.baseScore; e.v = String(best.baseSeverity || '').toUpperCase(); }
      else { e.s = null; e.ct = (e.ct || 0) + 1; }
    } catch (err) { if (/HTTP 404/.test(err.message)) { e.s = null; e.ct = (e.ct || 0) + 1; } }
  });
  const out = {};
  for (const id of ids) { const e = db[id]; if (!e) continue; out[id] = { ...(e.s != null ? { s: e.s, v: e.v } : {}), ...(e.e != null ? { e: e.e, p: e.p } : {}), ...(kevAll?.has(id) ? { k: 1 } : (e.k && !kevAll ? { k: 1 } : {})), d: e.d, ...(e.ct ? { ct: e.ct } : {}) }; }
  writeJson(file, { u: new Date().toISOString(), c: out });
  return out;
}

/* ------------------------------------------------------------ publication dates */
const metaOf = (h, names) => {
  for (const n of names) {
    const m = h.match(new RegExp('<meta[^>]+(?:property|name|itemprop)=["\']' + n + '["\'][^>]*content=["\']([^"\']+)', 'i')) || h.match(new RegExp('<meta[^>]+content=["\']([^"\']+)["\'][^>]*(?:property|name|itemprop)=["\']' + n + '["\']', 'i'));
    if (m) return decode(m[1]);
  }
  return '';
};
/** Real publication date of an article page (OpenGraph / JSON-LD / <time>), or null. */
function pageDate(h) {
  const cands = [];
  for (const n of ['article:published_time', 'og:published_time', 'datePublished', 'dc.date.issued', 'dcterms.created', 'dc.date', 'date', 'publish-date', 'pubdate', 'parsely-pub-date', 'sailthru.date']) { const v = metaOf(h, n); if (v) cands.push(v); }
  for (const m of h.matchAll(/"datePublished"\s*:\s*"([^"]+)"/g)) cands.push(m[1]);
  const tm = h.match(/<time[^>]+datetime=["']([^"']+)/i); if (tm) cands.push(tm[1]);
  for (const c of cands) { const d = toDate(c); if (d && d.getTime() <= Date.now() + 36e5 && d.getFullYear() >= 2015) return d; }
  return null;
}
/** Decide the publication date: feed date, corrected by the page's own date when that is earlier (feeds often
 *  carry the *updated* time); future dates are clamped to now; undated feed items take the page date. */
function resolveDate(feedDate, pageD, feedDateOnly = false) {
  const now = new Date();
  let d = feedDate, src = 'feed', dp = feedDateOnly ? 'd' : '';
  // a date-only feed item takes the page's real timestamp when it is the same day
  if (feedDateOnly && feedDate && pageD && Math.abs(pageD.getTime() - feedDate.getTime()) < 36 * 36e5) { d = pageD; src = 'page'; dp = ''; return { date: d, src, dp }; }
  if (d && d.getTime() > now.getTime() + 36e5) d = now;
  if (pageD && (!d || (pageD.getTime() < d.getTime() - 36e5 && d.getTime() - pageD.getTime() < 400 * 864e5))) { d = pageD; src = 'page'; }
  if (src === 'page') dp = '';
  return d ? { date: d, src, dp } : null;
}

/* ------------------------------------------------------------------- main */
async function main() {
  const t0 = Date.now();
  const sources = readJson(path.join(ROOT, 'collector', 'sources.json'), []);
  const store = FULL ? { reports: [] } : readJson(path.join(DATA, 'reports.json'), { reports: [] });
  const existing = new Map((store.reports || []).map(r => [r.id, r]));
  const srcById = new Map(sources.map(x => [x.id, x]));
  let retagged = 0;
  for (const r of existing.values()) if (!r.countries) { r.countries = detectCountries(r.title, r.summary || '', srcById.get(r.sourceId)?.country); retagged++; }
  if (retagged) log(`Re-tagged ${retagged} existing reports with countries.`);
  if (sources.length > 20) {
    let gone = 0;
    for (const r of [...existing.values()]) if (r.sourceId !== 'manual' && !srcById.has(r.sourceId)) { existing.delete(r.id); gone++; }
    if (gone) log(`Removed ${gone} reports of sources that are no longer in sources.json.`);
  }
  for (const r of existing.values()) if (!r.dp && /T00:00:00\.000Z$/.test(r.published)) r.dp = 'd';
  for (const r of existing.values()) if (r.sourceType === 'regional' && /news\.google\.com/.test(r.url)) r.countries = detectCountries(r.title, r.summary || '', srcById.get(r.sourceId)?.country);
  let offTopic = 0;
  for (const r of [...existing.values()]) {
    const sr = srcById.get(r.sourceId);
    if (!sr || sr.core || sr.type === 'gov' || r.sourceId === 'manual') continue;
    if (!(r.groups.length || r.cves.length || (r.techniques || []).length || isThreatText(r.title + ' ' + (r.summary || ''), r.title))) { existing.delete(r.id); offTopic++; }
  }
  if (offTopic) log(`Removed ${offTopic} stored items that are not about threats (marketing, tutorials, general news).`);
  for (const r of existing.values()) {      // country tags produced by the over-greedy aliases (Georgia = "грузит", India = "индикатор", Morocco = "fast")
    if (!r.countries || !r.countries.length) continue;
    if (/[\u0400-\u04FF]/.test(r.title)) { const ok = detectCountries(r.title, r.summary || '', null); r.countries = r.countries.filter(c => ok.includes(c)); }
    else if (r.countries.includes('MA') && !/morocc|maroc|المغرب/i.test(r.title + ' ' + (r.summary || ''))) r.countries = r.countries.filter(c => c !== 'MA');
  }
  // drop local-language regional reports stored under the older, looser relevance rule
  let purged = 0;
  for (const r of [...existing.values()]) {
    if (r.sourceType !== 'regional') continue;
    const tx = r.title + ' ' + (r.summary || '').slice(0, 400);
    if (!CYBER.test(tx) && !localCyber(tx)) { existing.delete(r.id); purged++; }
  }
  if (purged) log(`Removed ${purged} local-language items that are not about cyber security.`);
  const cutoff = Date.now() - MAX_AGE_DAYS * 864e5;
  const today = new Date().toISOString().slice(0, 10);

  for (const x of sources) { try { BENIGN.add(regDomain(new URL(x.url).hostname.replace(/^www\./, ''))); } catch { /* ignore */ } }
  log(`Fetching ${sources.length} feeds...`);
  const feedRes = await pool(sources, CONCURRENCY, async s => {
    let lastErr;
    for (const url of [s.url, ...(s.alt || [])]) {      // "alt" = backup addresses for the same feed
      try {
        const items = parseFeed(await get(url));
        if (items.length) return items;
        lastErr = new Error('no items parsed');
      } catch (e) { lastErr = e; }
    }
    throw lastErr;
  });
  const hostOf = u => { try { return new URL(u).hostname; } catch { return ''; } };
  const idOf = u => sha1(u.replace(/[?#].*$/, '').replace(/\/$/, '')).slice(0, 12);
  const nowIso = new Date().toISOString();
  const prevHealth = new Map((readJson(path.join(DATA, 'meta.json'), {}).sources || []).map(h => [h.id, h]));
  const health = [], candidates = [], seen = new Set();
  sources.forEach((s, i) => {
    const r = feedRes[i], prev = prevHealth.get(s.id) || {};
    if (!r || r.error) {
      health.push({ id: s.id, name: s.name, type: s.type, ok: false, error: r?.error || 'unknown', items: 0, new: 0, lastOk: prev.lastOk || null, fails: (prev.fails || 0) + 1, since: prev.since || nowIso, newest: prev.newest || null });
      log(`  x ${s.name}: ${r?.error}`); return;
    }
    let fresh = 0, newest = 0;
    for (const e of r) {
      const d = toDate(e.date);
      if (d && d.getTime() > newest && d.getTime() <= Date.now() + 36e5) newest = d.getTime();
      if (d && d.getTime() < cutoff) continue;
      const id = idOf(e.link);
      if (existing.has(id) || seen.has(id)) continue;
      if (s.type === 'regional') { const tx = e.title + ' ' + htmlToText(e.html).slice(0, 600); if (!CYBER.test(tx) && !localCyber(tx)) continue; }
      seen.add(id);
      candidates.push({ id, src: s, e, feedDate: d, feedDateOnly: isDateOnlyRaw(e.date) });      // undated items get their date from the article page
      fresh++;
    }
    health.push({ id: s.id, name: s.name, type: s.type, ok: true, items: r.length, new: fresh, lastOk: nowIso, fails: 0, newest: newest ? new Date(newest).toISOString() : null });
    log(`  ok ${s.name}: ${r.length} items, ${fresh} new`);
  });

  // Deep fetch: read the full article (IoC tables, country mentions, exact publish date) where the feed only had a teaser
  candidates.sort((a, b) => ((b.feedDate || 0) - (a.feedDate || 0)));
  const isNews = c => /news\.google\.com/.test(c.e.link);
  const wantsDeep = c => !isNews(c) && (!c.feedDate || c.src.core || c.src.type === 'gov' || isThreatText(c.e.title + ' ' + htmlToText(c.e.html).slice(0, 300), c.e.title)) && (!c.feedDate || htmlToText(c.e.html).length < 6000);
  const needDeep = candidates.filter(wantsDeep);
  const deepSet = new Set([...needDeep.filter(c => !c.feedDate), ...needDeep.filter(c => c.feedDate)].slice(0, MAX_DEEP_FETCH).map(c => c.id));
  log(`Candidates: ${candidates.length}; fetching ${deepSet.size} full articles...`);
  await pool(candidates.filter(c => deepSet.has(c.id)), CONCURRENCY, async c => {
    try {
      const h = await get(c.e.link, 20000); const txt = articleBody(h);
      if (txt.length > htmlToText(c.e.html).length) c.fullText = txt;
      c.pageDate = pageDate(h);
    } catch { /* keep teaser */ }
  });

  const newDaily = []; let added = 0, dropped = 0;

  // Turn a page of text into a report object + its IoCs (used for new feed items, manual links and upgrades)
  function analyze({ id, src, title, url, published, dateSrc, dp, feedText, fullText, collected, firstSeen }) {
    const text = (fullText || feedText).slice(0, MAX_TEXT);
    const { iocs, obs, total, hasDefang } = extractIocs(text, hostOf(url));
    const grp = attribute(title, text);
    const countries = detectCountries(title, text, src.country);
    const lang = detectLang(title + ' ' + text.slice(0, 500)), gh = glossHits(title + '\n' + text.slice(0, 3500));
    const tags = uniq([...TAGS.filter(([, re]) => re.test(title + ' ' + text.slice(0, 20000))).map(([n]) => n), ...gh.map(g => g.tag).filter(Boolean)]);
    const rep = {
      id, title: title.slice(0, 220), url, source: src.name, sourceId: src.id, sourceType: src.type,
      published, dateSrc: dateSrc || 'feed', ...(dp ? { dp } : {}), collected: collected || today, firstSeen: firstSeen || nowIso, summary: (feedText || text).replace(/\s+/g, ' ').slice(0, 260),
      groups: grp.map(g => ({ name: g.name, country: g.country, sponsor: g.sponsor })), tags, countries,
      cves: cves(text), techniques: techniques(text), iocCounts: Object.fromEntries(Object.entries(iocs).filter(([, v]) => v.length).map(([k, v]) => [k, v.length])),
      iocTotal: total, deep: !!fullText, defanged: hasDefang,
    };
    if (lang !== 'en') { rep.lang = lang; if (gh.length) rep.en = uniq(gh.map(g => g.en)).slice(0, 10); }
    rep.score = score(rep);
    return { rep, iocs, obs, total, grp };
  }
  function saveIocs(rep, iocs, total, obs = {}) {
    if (!total) return;
    const mf = path.join(IOCS, 'by-month', rep.published.slice(0, 7) + '.json');
    const month = readJson(mf, { entries: [] }).entries.filter(e => e.report.id !== rep.id);
    month.push({ report: { id: rep.id, title: rep.title, url: rep.url, source: rep.source, published: rep.published, groups: rep.groups.map(g => g.name), cves: rep.cves, techniques: rep.techniques }, iocs, obs });
    writeJson(mf, { entries: month });
    for (const [type, arr] of Object.entries(iocs)) for (const v of arr) newDaily.push({ type, value: v, report: rep.id, groups: rep.groups.map(g => g.name), published: rep.published, observed: obs[type + '|' + v] || null });
  }

  for (const c of candidates) {
    const when = resolveDate(c.feedDate, c.pageDate, c.feedDateOnly);           // exact publication date: never in the future, page date wins if earlier
    if (!when || when.date.getTime() < cutoff) { dropped++; continue; }
    const feedText = htmlToText(c.e.html);
    if (c.src.type === 'regional' && !CYBER.test(c.e.title + ' ' + feedText.slice(0, 600)) && !localCyber(c.e.title + ' ' + feedText.slice(0, 600))) continue;
    const { rep, iocs, obs, total, grp } = analyze({ id: c.id, src: c.src, title: c.e.title, url: c.e.link, published: when.date.toISOString(), dateSrc: when.src, dp: when.dp, feedText, fullText: c.fullText });
    // news / general vendor blogs without any threat relevance are dropped to keep the feed clean
    // not about threats (AI product marketing, tutorials, corporate news, sports...): dropped; indicators alone never prove relevance
    const relevant = grp.length || rep.cves.length || (rep.techniques || []).length || isThreatText(c.e.title + ' ' + feedText.slice(0, 300), c.e.title);
    if (!c.src.core && c.src.type !== 'gov' && !relevant) continue;
    existing.set(rep.id, rep); added++;
    saveIocs(rep, iocs, total, obs);
  }
  if (dropped) log(`Skipped ${dropped} items with no usable / too old publication date.`);

  // Manual links: put any report URL you don't want to miss into collector/extra-urls.txt (one per line)
  const pins = fs.existsSync(path.join(ROOT, 'collector', 'extra-urls.txt')) ? fs.readFileSync(path.join(ROOT, 'collector', 'extra-urls.txt'), 'utf8').split(/\r?\n/).map(x => x.trim()).filter(x => /^https?:\/\//.test(x)) : [];
  let pinned = 0;
  await pool(pins.filter(u => !existing.get(idOf(u))?.deep), 4, async u => {
    try {
      const h = await get(u, 25000); const txt = articleBody(h);
      const title = decode(metaOf(h, ['og:title', 'twitter:title']) || (h.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || u).replace(/\s+/g, ' ').trim();
      const pd = pageDate(h);
      const src = { id: 'manual', name: 'Pinned: ' + hostOf(u).replace(/^www\./, ''), type: 'research' };
      const { rep, iocs, obs, total } = analyze({ id: idOf(u), src, title, url: u, published: (pd || new Date()).toISOString(), dateSrc: pd ? 'page' : 'feed', feedText: txt.slice(0, 600), fullText: txt });
      existing.set(rep.id, rep); saveIocs(rep, iocs, total, obs); pinned++;
      log(`  pinned: ${title.slice(0, 80)} [${rep.countries.join(',')}]`);
    } catch (e) { log('  pin failed:', u, e.message); }
  });

  // Upgrade pass: reports that were stored from the feed teaser only get their full article re-fetched
  // (a few per run), so country / IoC / ATT&CK extraction and the publish date improve over time.
  const MAX_UPGRADE = +process.env.MAX_UPGRADE || 80; let upgraded = 0;
  const todo = [...existing.values()].filter(r => !r.deep && (r.tries || 0) < 3 && ['research', 'gov', 'vendor'].includes(r.sourceType) && !/news\.google\.com/.test(r.url))
    .sort((x, y) => (x.published < y.published ? 1 : -1)).slice(0, MAX_UPGRADE);
  await pool(todo, CONCURRENCY, async r => {
    try {
      const h = await get(r.url, 20000); const txt = articleBody(h);
      if (txt.length < (r.summary || '').length * 1.5) throw new Error('short');
      const src = srcById.get(r.sourceId) || { id: r.sourceId, name: r.source, type: r.sourceType };
      const when = resolveDate(new Date(r.published), pageDate(h), r.dp === 'd');
      const { rep, iocs, obs, total } = analyze({ id: r.id, src, title: r.title, url: r.url, published: when.date.toISOString(), dateSrc: when.src === 'page' ? 'page' : (r.dateSrc || 'feed'), dp: when.dp, feedText: r.summary, fullText: txt, collected: r.collected, firstSeen: r.firstSeen });
      existing.set(r.id, rep); saveIocs(rep, iocs, total, obs); upgraded++;
    } catch { r.tries = (r.tries || 0) + 1; }
  });
  if (pinned || upgraded) log(`Pinned ${pinned}, upgraded ${upgraded} teaser-only reports to full text.`);
  log(`Added ${added} reports, ${newDaily.length} IoC records.`);

  // Direct IoC feeds (C2 trackers / blocklists): current snapshot kept in site/iocs/live/<id>.json, entries expire after ttlDays
  const liveFeeds = readJson(path.join(ROOT, 'collector', 'ioc-feeds.json'), []);
  const parseLive = (txt, type) => {
    const out = new Set();
    for (const raw of txt.split(/\r?\n/).slice(0, 40000)) {
      const line = raw.trim(); if (!line || /^[#;]/.test(line)) continue;
      const tok = line.split(/[\s,;|]+/)[0].replace(/^["']|["']$/g, '');
      if (type === 'ipv4') { if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(tok) && tok.split('.').every(n => +n <= 255) && !isPrivateIp(tok) && !EXCLUDE_IP.has(tok)) out.add(tok); }
      else if (type === 'url') { if (/^https?:\/\/\S+$/i.test(line)) out.add(line.slice(0, 300)); }
      else if (type === 'domain') { const d = tok.toLowerCase(); if (/^(?:[a-z0-9-]+\.)+[a-z]{2,24}$/.test(d) && !isBenign(d)) out.add(d); }
    }
    return [...out];
  };
  const liveHealth = [];
  await pool(liveFeeds, 4, async lf => {
    const file = path.join(IOCS, 'live', lf.id + '.json');
    const map = new Map(readJson(file, { items: [] }).items.map(i => [i.v, i]));
    const h = { id: lf.id, name: lf.name, type: lf.type, ok: false, items: 0 };
    try {
      const vals = parseLive(await get(lf.url, 40000), lf.type);
      if (!vals.length) throw new Error('empty list');
      for (const v of vals) { const e = map.get(v); if (e) e.last = nowIso; else { map.set(v, { v, first: nowIso, last: nowIso }); newDaily.push({ type: lf.type, value: v, report: null, source: lf.name, groups: [], published: nowIso, observed: null }); } }
      h.ok = true; h.listed = vals.length;
    } catch (e) { h.error = e.message; log('  x IoC feed', lf.name + ':', e.message); }
    const ttl = (lf.ttlDays || 7) * 864e5;
    const items = [...map.values()].filter(i => Date.now() - new Date(i.last).getTime() <= ttl).sort((a, b) => (a.first < b.first ? 1 : -1)).slice(0, lf.cap || 500);
    if (items.length || fs.existsSync(file)) writeJson(file, { id: lf.id, name: lf.name, type: lf.type, updated: nowIso, items });
    h.items = items.length; liveHealth.push(h);
  });
  if (liveFeeds.length) log(`IoC feeds: ${liveHealth.filter(x => x.ok).length}/${liveFeeds.length} ok, ${liveHealth.reduce((n, x) => n + x.items, 0)} live indicators.`);

  // retention
  const keepFrom = Date.now() - RETAIN_DAYS * 864e5;
  const reports = [...existing.values()].filter(r => new Date(r.published).getTime() >= keepFrom).sort((a, b) => (a.published < b.published ? 1 : -1)).slice(0, 6000);
  const byId = new Map(reports.map(r => [r.id, r]));
  const storyCount = clusterStories(reports);
  log('Stories (grouped duplicate coverage): ' + storyCount);

  // aggregate IoCs from the archive folder (source of truth)
  const agg = new Map();
  const walk = d => fs.existsSync(d) ? fs.readdirSync(d, { withFileTypes: true }).flatMap(f => f.isDirectory() ? walk(path.join(d, f.name)) : f.name.endsWith('.json') ? [path.join(d, f.name)] : []) : [];
  for (const f of walk(path.join(IOCS, 'by-month'))) for (const j of readJson(f, { entries: [] }).entries) {
    if (!byId.has(j.report.id)) continue;
    for (const [type, arr] of Object.entries(j.iocs)) for (const v of arr) {
      const k = type + '|' + v; let e = agg.get(k);
      const when = (j.obs && j.obs[k]) ? j.obs[k] + 'T00:00:00.000Z' : j.report.published;
      if (!e) agg.set(k, e = { t: type, v, r: [], g: [], s: [], first: when, last: when });
      if (!e.r.includes(j.report.id)) e.r.push(j.report.id);
      for (const g of j.report.groups) if (!e.g.includes(g)) e.g.push(g);
      if (when < e.first) e.first = when; if (when > e.last) e.last = when;
    }
  }
  for (const lf of liveFeeds) for (const it of readJson(path.join(IOCS, 'live', lf.id + '.json'), { items: [] }).items) {
    const k = lf.type + '|' + it.v; let e = agg.get(k);
    if (!e) agg.set(k, e = { t: lf.type, v: it.v, r: [], g: [], s: [], first: it.first, last: it.last });
    if (!e.s.includes(lf.name)) e.s.push(lf.name);
    if (it.first < e.first) e.first = it.first; if (it.last > e.last) e.last = it.last;
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
  const csv = ['type,value,first_seen,last_seen,groups,report_count,report_ids,feeds'].concat(allIocs.map(e => [e.t, e.v, e.first.slice(0, 10), e.last.slice(0, 10), e.g.join('|'), e.r.length, e.r.join('|'), (e.s || []).join('|')].map(x => `"${String(x).replace(/"/g, '""')}"`).join(','))).join('\n');
  writeText(path.join(IOCS, 'all.csv'), csv + '\n');
  const header = `# ThreatLens IoC feed - generated ${new Date().toISOString()} - source: public vendor reports. Verify before blocking.\n`;
  for (const t of ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'sha512', 'email', 'wallet', 'file']) writeText(path.join(IOCS, 'feeds', `${t}.txt`), header + allIocs.filter(e => e.t === t).map(e => e.v).join('\n') + '\n');

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
  let kev = readJson(path.join(DATA, 'kev.json'), null), kevAll = null;
  try {
    const k = JSON.parse(await get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 40000));
    const list = (k.vulnerabilities || []).sort((a, b) => (a.dateAdded < b.dateAdded ? 1 : -1));
    kevAll = new Set(list.map(v => v.cveID));
    kev = { updated: new Date().toISOString(), total: list.length, catalogVersion: k.catalogVersion, ransomware: list.filter(v => v.knownRansomwareCampaignUse === 'Known').length,
      latest: list.slice(0, 80).map(v => ({ cve: v.cveID, vendor: v.vendorProject, product: v.product, name: v.vulnerabilityName, added: v.dateAdded, due: v.dueDate, ransomware: v.knownRansomwareCampaignUse === 'Known', desc: (v.shortDescription || '').slice(0, 280) })) };
    log(`KEV: ${kev.total} entries`);
  } catch (e) { log('KEV fetch failed:', e.message); }
  if (kev) writeJson(path.join(DATA, 'kev.json'), kev);

  // CVE scores (EPSS + CVSS) for every CVE mentioned in the last 120 days + the latest KEV entries
  const cveIds = [], cseen = new Set(), addCve = c => { if (!cseen.has(c)) { cseen.add(c); cveIds.push(c); } };
  for (const r of reports) if (Date.now() - new Date(r.published).getTime() < 120 * 864e5) for (const c of r.cves) addCve(c);
  for (const v of kev?.latest || []) addCve(v.cve);
  const cdb = await enrichCves(cveIds, kevAll);
  log('CVE scores: ' + Object.keys(cdb).length + ' CVEs, ' + Object.values(cdb).filter(x => x.s !== undefined).length + ' with CVSS, ' + Object.values(cdb).filter(x => x.e !== undefined).length + ' with EPSS');

  // CVE mention leaderboard
  const cveCount = {}; for (const r of reports) for (const c of r.cves) cveCount[c] = (cveCount[c] || 0) + 1;
  const kevSet = new Set((kev?.latest || []).map(v => v.cve));
  const topCves = Object.entries(cveCount).sort((a, b) => b[1] - a[1]).slice(0, 30).map(([cve, n]) => ({ cve, n, kev: kevSet.has(cve) }));

  // trending CVEs: mentioned by many distinct reports in the last 24-72 h, boosted by CISA KEV and high EPSS
  const tt24 = Date.now() - 864e5, tt72 = Date.now() - 3 * 864e5, tt7 = Date.now() - 7 * 864e5, cstat = new Map();
  for (const r of reports) { const t = new Date(r.published).getTime(); if (t < tt7) continue; for (const c of r.cves) { let x = cstat.get(c); if (!x) cstat.set(c, x = { cve: c, m24: 0, m72: 0, m7: 0, src: new Set(), last: t }); x.m7++; if (t >= tt72) x.m72++; if (t >= tt24) x.m24++; x.src.add(r.sourceId); if (t > x.last) x.last = t; } }
  const trending = [...cstat.values()].map(x => { const d = cdb[x.cve] || {}, kv = !!d.k || kevSet.has(x.cve);
    return { cve: x.cve, m24: x.m24, m72: x.m72, m7: x.m7, src: x.src.size, last: new Date(x.last).toISOString(), kev: kv,
      score: 3 * x.m24 + 1.5 * (x.m72 - x.m24) + 0.5 * (x.m7 - x.m72) + 0.4 * Math.min(x.src.size, 10) + (kv ? 4 : 0) + ((d.e || 0) >= 0.5 ? 3 : (d.e || 0) >= 0.1 ? 1.5 : 0) }; })
    .filter(x => x.m72 >= 2 || (x.kev && x.m72 >= 1)).sort((a, b) => b.score - a.score).slice(0, 15).map(({ score, ...x }) => x);
  const langCount = {}; for (const r of reports) if (r.lang) langCount[r.lang] = (langCount[r.lang] || 0) + 1;

  // stats
  const daily = {}; for (let i = 59; i >= 0; i--) daily[new Date(Date.now() - i * 864e5).toISOString().slice(0, 10)] = { reports: 0, iocs: 0 };
  for (const r of reports) { const d = r.published.slice(0, 10); if (daily[d]) { daily[d].reports++; daily[d].iocs += r.iocTotal; } }
  const tagCount = {}; for (const r of reports) for (const t of r.tags) tagCount[t] = (tagCount[t] || 0) + 1;
  const techCount = {}; for (const r of reports) for (const t of r.techniques) techCount[t.split('.')[0]] = (techCount[t.split('.')[0]] || 0) + 1;
  const countryCount = {}; for (const g of groupList) countryCount[g.country] = (countryCount[g.country] || 0) + g.reportCount;
  const mentionCount = {}; const since90 = Date.now() - 90 * 864e5;
  for (const r of reports) if (new Date(r.published).getTime() > since90) for (const c of r.countries || []) mentionCount[c] = (mentionCount[c] || 0) + 1;
  const week = Date.now() - 7 * 864e5;
  const meta = {
    updated: new Date().toISOString(), runSeconds: Math.round((Date.now() - t0) / 1000),
    totals: { reports: reports.length, groups: groupList.length, iocs: allIocs.length, cves: Object.keys(cveCount).length, sources: sources.length, sourcesOk: health.filter(h => h.ok).length,
      reports7d: reports.filter(r => new Date(r.published).getTime() > week).length, newThisRun: added, iocsThisRun: newDaily.length },
    iocTypes: typeTotals, iocFeeds: liveHealth, daily, tags: tagCount, techniques: Object.entries(techCount).sort((a, b) => b[1] - a[1]).slice(0, 25), countries: countryCount, mentions: mentionCount, topCves, trending, langs: langCount, stories: storyCount, sources: health,
  };
  writeJson(path.join(DATA, 'meta.json'), meta);
  writeJson(path.join(DATA, 'groups.json'), groupList);
  writeJson(path.join(DATA, 'countries.json'), countryList.map(({ code, name, aliases }) => ({ code, name, aliases: aliases.map(a => a.replace(/^[=^]/, '').replace(/~$/, '')) })));
  writeJson(path.join(DATA, 'reports.json'), { updated: meta.updated, schema: SCHEMA, reports });
  log(`Done in ${meta.runSeconds}s: ${reports.length} reports, ${groupList.length} groups, ${allIocs.length} unique IoCs.`);
}
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) main().catch(e => { console.error('Collector failed:', e); process.exit(0); /* never fail the workflow/build */ });
export { extractIocs, htmlToText, articleBody, parseFeed, detectCountries, attribute, refang, pageDate, resolveDate, glossHits, localCyber, detectLang, clusterStories, foldLatin, normAr, normHe, toDate, isDateOnlyRaw };
