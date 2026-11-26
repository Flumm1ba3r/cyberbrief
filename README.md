# CyberBrief

A personal cybersecurity news briefing that works on your phone. Every hour it collects news from 25 established sources, groups the articles that cover the same event, ranks the stories by importance, and gives each one a short summary with a link to the full article.

## How it works

- **Sources** (`sources.json`) are official agencies (CISA and its Known Exploited Vulnerabilities list, NCSC UK, Australia's ACSC, Singapore's CSA), research teams (Microsoft, Google, Talos, Unit 42, ESET, SentinelLabs, Citizen Lab, SANS ISC, Project Zero, Schneier), security news outlets (BleepingComputer, The Record, SecurityWeek, Krebs, Ars Technica, CyberScoop, TechCrunch, Dark Reading, The Register, Wired, Risky Business News), and publishers of incident postmortems (Cloudflare, GitHub's availability reports, The DFIR Report). Each was checked to work from GitHub's servers (`feedcheck/`).
- **Ranking**: a story ranks higher when several sources cover it, when it involves active exploitation, ransomware, breaches, supply-chain attacks or nation-state actors, and when it is recent. Promotions, webinars, podcasts and funding news are dropped or pushed down.
- **Summaries**: if an Anthropic API key is configured, Claude writes a 2–3 sentence summary and a "why it matters" line for each story, and rates its importance. Without a key, the app shows each outlet's own excerpt instead. A story is only summarized once, unless a new source joins it.
- **Follow-ups**: new stories are compared with a 120-day archive. When a later article continues an earlier story (same CVE, or same incident confirmed by Claude), it is shown as an **Update** with a timeline of the earlier coverage. Without Claude, only clear matches (a shared CVE or near-identical headline) are linked.
- **Deep dives**: postmortems, root-cause reports and incident investigations are marked and stay available for 30 days.
- **CVE details**: each CVE shows its CVSS severity (from the official CVE record) and its EPSS score, the probability of exploitation in the next 30 days (from FIRST).
- **Week**: the 10 most important stories of the past 7 days, with a short recap written by Claude.
- **The app** (`site/`) is a static web app hosted on GitHub Pages. You can install it on your phone's home screen, and it works offline with the last briefing. It has Top, Latest, Week and Saved views, filters (watchlist, CVE, deep dives, categories) and search. Tap a headline for the story page: every source, the timeline, CVE details and why the story is in your briefing. Settings hold your watchlist (vendors or products you care about, highlighted and ranked higher), a compact headlines-only list, muted sources and categories, "hide stories I've read" and "mark all as read". Installed on a phone, the app icon shows how many stories from the last 24 hours you haven't read (updated when the app is opened). Watchlist, saved stories and read state are stored on your device only.

The build runs in GitHub Actions (`.github/workflows/briefing.yml`): `scripts/build-briefing.mjs` writes `site/data/briefing.json` (what the app shows) and `site/data/state.json` (the archive and caches the next run builds on), and the `site/` folder is deployed to Pages.

## Setup

1. **Enable GitHub Pages**: Settings → Pages → Build and deployment → Source: **GitHub Actions**.
2. **(Optional) Add Claude summaries**: Settings → Secrets and variables → Actions → New repository secret named `ANTHROPIC_API_KEY`. The default model is `claude-opus-5-5`. To use a cheaper one, add a repository *variable* `CLAUDE_MODEL`, e.g. `claude-haiku-5-5`.
3. **Run it**: Actions → Briefing → Run workflow. After that it runs every hour.
4. **Open it** at `https://<your-username>.github.io/cyberbrief/`. On iPhone, tap Share → Add to Home Screen; on Android, use the browser menu → Install app.

### Push alerts (optional)

CyberBrief can send critical stories to your phone with the free [ntfy](https://ntfy.sh) app (developer: Philipp Heckel).

1. Install ntfy and subscribe to a topic with a long, hard-to-guess name. Anyone who knows the name can read the alerts.
2. Add it as a repository **secret** named `NTFY_TOPIC`. The next run sends a "CyberBrief alerts are on" test message.
3. Optionally add a repository **variable** `ALERT_WATCHLIST`, e.g. `Microsoft, Fortinet, Cisco, Singapore`.

4. Optionally add a daily top-5 notification: a **secret** (or variable) `DIGEST` with the local time and time zone, e.g. `08:00 Asia/Singapore`. A secret keeps your time zone out of the public run logs. It usually arrives between about 10 minutes before and 5 minutes after the set time (GitHub sometimes starts scheduled runs late).

5. Optionally add quiet hours: a **secret** `QUIET_HOURS`, e.g. `23:00-07:00 Asia/Singapore`. Nothing is sent during those hours; alerts that are still relevant arrive with the first run afterwards (around 7:50).

You get an alert for stories rated 5/5 (critical), for watchlist matches that are exploited (KEV, actively exploited CVE) or rated 4+, and for follow-ups to important stories. Each story alerts once; at most 4 alerts per run, with any extra rolled into one summary.

CyberBrief also tells you when it needs attention: an alert when a source has been failing for a day, when Claude summaries stop working (e.g. no API credit left) and when they recover. The app warns when the briefing is more than 3 hours old.

GitHub pauses scheduled workflows in public repositories after 60 days without commits. The weekly `Keep schedule alive` workflow (`.github/workflows/keepalive.yml`) re-enables the schedule and, if the repository has been quiet for 45 days, commits a timestamp to `.github/keepalive`.

## Local development

```bash
npm ci
npm run build          # fetches all feeds; set ANTHROPIC_API_KEY to test summaries
cd site && python3 -m http.server 8000
```

To build without network access, point `CYBERBRIEF_FIXTURES` at a folder of `<source-id>.xml` files (and `cisa-kev.json`).
