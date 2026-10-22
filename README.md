# ThreatLens

Threat-intelligence dashboard. A zero-dependency Node collector pulls ~195 public sources (threat-research teams,
vendor blogs, national CERTs, UK + global security press, regional news, CISA KEV) plus direct IoC feeds,
attributes reports to APT / crimeware groups, tags countries, extracts IoCs / CVEs / ATT&CK IDs and writes static files.
A GitHub Action runs it **every 45 minutes**; the site reads the data live from the repo.

```
collector/collect.mjs      the collector (Node 18+, no npm install)
collector/sources.json     feed list. type: research | vendor | gov | news | regional.  "alt": backup addresses
collector/ioc-feeds.json   direct IoC feeds (C2 trackers, blocklists) - kept with an expiry (ttlDays)
collector/groups.json      actor names + aliases
collector/countries.json   country names / demonyms / capitals / Russian stems -> country search
collector/extra-urls.txt   report URLs you never want to miss (one per line)
site/                      what Render/Netlify publishes (index.html app.js style.css)
  data/                    reports.json groups.json meta.json kev.json countries.json
  iocs/                    all.json all.csv feeds/*.txt by-month/*.json daily/*.json live/*.json
.github/workflows/         scheduled collection (every 45 min) + manual "Run workflow"
```

## What is extracted
* IoC types: IPv4, IPv6, domains, URLs, MD5, SHA-1, SHA-256, SHA-512, e-mail, crypto wallets, file names.
* An indicator is accepted when it is defanged, sits in/after an "IOCs / Indicators / Hashes / C2" heading, has
  C2/server/IP wording nearby, or is part of a list/table (several indicators of one kind close together).
  Observed dates written next to an indicator (e.g. an "IP Address | Observed Date" table) are kept.
* Publication date: the feed date, corrected by the article page's own `published` date when that is earlier;
  future dates are clamped; items without a date take it from the page or are skipped.
* Reports stored from a feed teaser are re-fetched in full (80 per run) so extraction improves over time.

## Run locally
    node collector/collect.mjs            # incremental
    FULL=1 node collector/collect.mjs     # rebuild from the feeds' current contents
    npx serve site

## Notes
* The site reads `data/*.json` from `raw.githubusercontent.com/<user>/threatlens/main/site/` (see `REMOTE` in `site/app.js`);
  if you rename the repo or user, change it there. A banner offers a refresh when newer data is published.
* IoCs are auto-extracted and may contain false positives; they are defanged in the UI. Direct feeds are community
  blocklists - verify before blocking.
* Some sites block cloud IPs; single feeds can fail on a run - see the "Sources" tab (shows failing-since and latest post).
