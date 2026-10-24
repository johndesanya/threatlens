#!/usr/bin/env node
/**
 * Integrity gate, run by the workflow BEFORE new data is committed.
 * A corrupted run, a broken feed parser or a tampered file must never replace good data on the live site.
 * Exit code 1 = do not publish.
 */
import fs from 'node:fs';
import { execSync } from 'node:child_process';

const fail = m => { console.error('SANITY FAIL: ' + m); process.exit(1); };
const read = p => { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { return fail(p + ' is missing or not valid JSON (' + e.message + ')'); } };

const cur = read('site/data/reports.json'), meta = read('site/data/meta.json');
read('site/data/groups.json'); read('site/data/countries.json'); read('site/data/cves.json');
if (!Array.isArray(cur.reports) || cur.reports.length < 500) fail('too few reports: ' + (cur.reports || []).length);

// a normal run never loses most of the history
let prev = null;
try { prev = JSON.parse(execSync('git show HEAD:site/data/reports.json', { maxBuffer: 1 << 29, stdio: ['ignore', 'pipe', 'ignore'] }).toString()); } catch { /* first run or file not yet tracked */ }
if (prev && !process.env.FULL && cur.reports.length < prev.reports.length * 0.6) fail('reports dropped from ' + prev.reports.length + ' to ' + cur.reports.length);

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
console.log('sanity ok: ' + cur.reports.length + ' reports, ' + (t.sourcesOk || '?') + '/' + (t.sources || '?') + ' sources');
