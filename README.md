# ThreatLens

Threat-intelligence dashboard. A zero-dependency Node collector pulls ~120 public sources (vendor research, national CERTs,
regional + global news, CISA KEV), attributes reports to APT / crimeware groups, tags **countries**, extracts IoCs / CVEs /
ATT&CK IDs and writes static files. A GitHub Action runs it every 3 hours; the site reads the data live from the repo.

```
collector/collect.mjs     the collector (Node 18+, no npm install)
collector/sources.json    feed list - add/remove feeds here ("country" tags a source to a country)
collector/groups.json     actor names + aliases
collector/countries.json  country names, demonyms, capitals, Russian stems -> used for country search
site/                     what Netlify publishes (index.html app.js style.css)
  data/                   reports.json groups.json meta.json kev.json countries.json
  iocs/                   all.json all.csv feeds/*.txt by-month/*.json daily/*.json
.github/workflows/        scheduled collection (every 3 hours) + manual "Run workflow"
```

## Why the site stays fresh without redeploys
`site/app.js` loads `data/*.json` from `raw.githubusercontent.com/<user>/threatlens/main/site/` (see `REMOTE`).
The GitHub Action commits new data, the page picks it up within ~5 minutes. Netlify only rebuilds when the front-end
files change (`ignore` rule in `netlify.toml`), which keeps you inside Netlify's free limits.
If you rename the repo or user, change `REMOTE` in `site/app.js`.

## Run locally
    node collector/collect.mjs            # incremental
    FULL=1 node collector/collect.mjs     # rebuild from the feeds' current contents
    npx serve site

## Notes
- IoCs are auto-extracted from prose and may contain false positives; they are defanged in the UI.
- Some sites block cloud IPs (Cloudflare), so single feeds can fail on some runs - see the "Sources" tab.
- Georgian / Armenian / Azerbaijani CERTs publish no RSS; those countries are covered through targeted news queries
  and through every vendor report that mentions them.
