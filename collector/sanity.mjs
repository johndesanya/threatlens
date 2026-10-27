#!/usr/bin/env node
/**
 * Integrity gate, run by the workflow BEFORE new data is committed.
 * A corrupted run, a broken feed parser, a size-limit bug or a tampered file must never replace good data on the live site.
 * Exit code 1 = do not publish.   ALLOW_SHRINK=1 skips the "history must not shrink" checks (deliberate clean-ups only).
 */
import fs from 'node:fs';
import { execSync } from 'node:child_process';

const fail = m => { console.error('SANITY FAIL: ' + m); process.exit(1); };
const read = p => { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { return fail(p + ' is missing or not valid JSON (' + e.message + ')'); } };
const prevOf = p => { try { return JSON.parse(execSync('git show HEAD:' + p, { maxBuffer: 1 << 29, stdio: ['ignore', 'pipe', 'ignore'] }).toString()); } catch { return null; } };

const cur = read('site/data/reports.json'), meta = read('site/data/meta.json');
read('site/data/groups.json'); read('site/data/countries.json'); read('site/data/cves.json');
const iocs = read('site/iocs/all.json');
if (!Array.isArray(cur.reports) || cur.reports.length < 500) fail('too few reports: ' + (cur.reports || []).length);

const groupsOf = reports => new Set(reports.flatMap(r => (r.groups || []).map(g => g.name)));
const attributed = reports => reports.filter(r => r.groups && r.groups.length).length;

// history must never shrink: reports, actor-attributed reports, distinct threat actors, indicators
const prev = prevOf('site/data/reports.json');
if (prev && !process.env.FULL && !process.env.ALLOW_SHRINK) {
  const p = prev.reports || [];
  if (cur.reports.length < p.length * 0.9) fail('reports dropped from ' + p.length + ' to ' + cur.reports.length);
  if (attributed(cur.reports) < attributed(p) * 0.92) fail('actor-attributed reports dropped from ' + attributed(p) + ' to ' + attributed(cur.reports) + ' - APT history is being lost');
  if (groupsOf(cur.reports).size < groupsOf(p).size * 0.92) fail('threat actors dropped from ' + groupsOf(p).size + ' to ' + groupsOf(cur.reports).size);
  const pi = prevOf('site/iocs/all.json');
  if (pi && iocs.length < pi.length * 0.85) fail('indicators dropped from ' + pi.length + ' to ' + iocs.length);
}

// most sources must have answered, otherwise the network (not the data) is broken
const t = meta.totals || {};
if (t.sources && t.sourcesOk < Math.max(20, t.sources * 0.5)) fail('only ' + t.sourcesOk + ' of ' + t.sources + ' sources responded');

// every record must be well-formed and safe to link to
const now = Date.now();
for (const r of cur.reports) {
  if (typeof r.id !== 'string' || typeof r.title !== 'string') fail('malformed record ' + JSON.stringify(r).slice(0, 80));
  if (!/^https?:\/\/[^\s<>"']+$/i.test(r.url || '')) fail('unsafe or malformed url in ' + r.id + ': ' + String(r.url).slice(0, 80));
  const d = Date.parse(r.published);
  if (isNaN(d) || d > now + 36e5) fail('bad publication date in ' + r.id + ': ' + r.published);
}
console.log('sanity ok: ' + cur.reports.length + ' reports (' + attributed(cur.reports) + ' attributed to ' + groupsOf(cur.reports).size + ' actors), ' + iocs.length + ' IoCs, ' + (t.sourcesOk || '?') + '/' + (t.sources || '?') + ' sources');
