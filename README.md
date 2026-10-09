# ThreatLens

Daily-updating threat-intelligence dashboard. A zero-dependency Node collector pulls ~35 public sources (vendor research, CERT advisories, news, CISA KEV), attributes reports to APT/crimeware groups, extracts IoCs / CVEs / ATT&CK IDs, and writes static files that Netlify serves.

```
collector/collect.mjs   the collector (Node 18+, no npm install)
collector/sources.json  feed list – add/remove feeds here
collector/groups.json   actor names + aliases + origin – extend freely
site/                   what Netlify publishes
  index.html app.js style.css
  data/                 reports.json groups.json meta.json kev.json
  iocs/                 <- extracted IoCs live here
    all.json all.csv    deduplicated, with first/last seen, actors, report ids
    feeds/*.txt         plain blocklists: ipv4 domain url md5 sha1 sha256 email
    by-month/YYYY-MM.json  IoCs per report, grouped by month
    daily/YYYY-MM-DD.json   what was newly collected on that day
```

## Run locally
```
node collector/collect.mjs      # incremental
FULL=1 node collector/collect.mjs   # rebuild everything
npx serve site                  # or any static server
```

## Deploy to Netlify
1. Push this folder to a GitHub repo.
2. Netlify → *Add new site → Import from Git*. Settings are read from `netlify.toml` (build: `node collector/collect.mjs`, publish: `site`).
3. **Daily refresh** – pick one:
   - Included: `.github/workflows/daily-collect.yml` runs the collector twice a day and commits fresh data; Netlify redeploys on push.
   - Or: Netlify → *Site settings → Build hooks* → create a hook, then call it daily from cron-job.org / a GitHub Action (`curl -X POST <hook-url>`). Every build re-collects.
4. Drag-and-drop also works: run the collector locally, then drop the `site/` folder onto Netlify Drop.

## Notes
- IoCs are auto-extracted from prose and may contain false positives; defanged by default in the UI.
- Extraction is context-aware (defanged forms, IoC sections, nearby "C2/server/IP" wording), and ignores major benign domains.
- Only public OSINT sources are used. Respect each source's terms; the collector sends a descriptive User-Agent and only fetches new articles.
