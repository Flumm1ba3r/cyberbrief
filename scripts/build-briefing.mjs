// Builds the briefing the app reads (site/data/briefing.json) and the state the next run builds on (site/data/state.json).
// Run by .github/workflows/briefing.yml every hour. Locally: `npm run build` (needs network access to the feeds),
// or offline with CYBERBRIEF_FIXTURES=<dir of <source-id>.xml files>.
//
// Steps: fetch every source → group coverage of the same event into stories → summarize and rate (Claude, optional)
// → link follow-ups to earlier stories → add CVE details → rank → pick the week's top stories.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { loadSource, truncate } from './lib/feeds.mjs';
import {
  isNoise, cvesIn, cluster, baseScore, finalScore, guessCategory, storyId, contentKey, tokens, jaccard, looksLikeDeepDive, properNames,
} from './lib/rank.mjs';
import { enrichCves } from './lib/cve.mjs';
import { alertReason, sendAlerts, watchTerms, checkHealth, sendDigest, dailySchedule } from './lib/alerts.mjs';

const ROOT = new URL('../', import.meta.url);
const OUT_DIR = new URL('site/data/', ROOT);

const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;
const WINDOW_DAYS = 7; // news older than this leaves the feed
const DEEP_DIVE_DAYS = 30; // postmortems and incident write-ups stay longer
const ARCHIVE_DAYS = 120; // how far back follow-ups are matched
const SUMMARIZE_HOURS = 72; // only recent stories are sent to Claude…
const SUMMARIZE_MAX = 45; // …and at most this many per run
const FOLLOWUP_CHECKS_MAX = 40; // possible follow-ups Claude checks per run
const RECAP_EVERY_HOURS = 6;
const MAX_STORIES = 250;
const KEV_CATALOG = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog';

const log = (...a) => console.log(...a);
const now = Date.now();
const nowIso = new Date(now).toISOString();
const ageOf = (iso) => now - Date.parse(iso);

async function pool(items, n, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: n }, async () => {
    while (next < items.length) { const i = next++; out[i] = await fn(items[i], i); }
  }));
  return out;
}

/** The previous run's output, from the live site (env var) or the local file. */
async function loadPrevious(envVar, file) {
  const url = process.env[envVar];
  try {
    if (url) {
      const res = await fetch(url, { headers: { 'Cache-Control': 'no-cache' } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    }
    return JSON.parse(await readFile(new URL(file, OUT_DIR), 'utf8'));
  } catch (e) {
    log(`No previous ${file} (${url || 'local file'}): ${e.message}`);
    return null;
  }
}

// --- 1. fetch ---------------------------------------------------------------

const { sources } = JSON.parse(await readFile(new URL('sources.json', ROOT), 'utf8'));
const previous = await loadPrevious('PREVIOUS_URL', 'briefing.json');
const state = (await loadPrevious('STATE_URL', 'state.json')) || {};
const archive = state.archive || {}; // story id -> compact record, for follow-ups
const cveCache = state.cves || {};
const pairCache = state.pairs || {}; // "laterId|earlierId" -> { f: is follow-up, n: note }

const prevFirstSeen = new Map();
const summaryCache = new Map(); // contentKey -> Claude's result from an earlier run
for (const s of previous?.stories || []) {
  for (const src of s.sources) prevFirstSeen.set(src.url, src.firstSeen || src.published);
  if (s.summarizedBy === 'claude') {
    summaryCache.set(s.key, { summary: s.summary, whyItMatters: s.whyItMatters, importance: s.importance, category: s.category, deepDive: s.deepDive });
  }
}
const mergedGroups = (state.mergedUrls || previous?.mergedUrls || []).map((g) => new Set(g));

log(`Fetching ${sources.length} sources…`);
const status = [];
const results = await pool(sources, 6, async (src) => {
  const started = Date.now();
  try {
    const items = await loadSource(src);
    status.push({ id: src.id, name: src.name, ok: true, items: items.length, ms: Date.now() - started });
    return { src, items };
  } catch (e) {
    status.push({ id: src.id, name: src.name, ok: false, error: e.message });
    log(`  ✗ ${src.id}: ${e.message}`);
    return { src, items: [] };
  }
});
log(`  ${status.filter((s) => s.ok).length}/${sources.length} sources OK`);

// --- 2. normalise items -------------------------------------------------------

const normUrl = (u) => u.replace(/[?#].*$/, '').replace(/\/$/, '');
const seenUrls = new Set();
const items = [];
let kevEntries = [];

for (const { src, items: raw } of results) {
  if (src.kind === 'kev') { kevEntries = raw; continue; }
  for (const it of raw) {
    const key = normUrl(it.url);
    if (seenUrls.has(key)) continue;
    seenUrls.add(key);
    const firstSeen = prevFirstSeen.get(it.url) || nowIso;
    // Undated items, or dates in the future, fall back to when CyberBrief first saw them.
    const published = it.published && Date.parse(it.published) <= now + HOUR ? it.published : firstSeen;
    const deepDive = !!src.deepDive || looksLikeDeepDive(it.title);
    if (ageOf(published) > (deepDive ? DEEP_DIVE_DAYS : WINDOW_DAYS) * DAY || isNoise(it)) continue;
    items.push({ ...it, published, firstSeen, deepDive, deepDiveSource: !!src.deepDive, sourceId: src.id, sourceName: src.name, sourceType: src.type, weight: src.weight });
  }
}

// CISA KEV: one story per day entries were added. CISA's own "adds N vulnerabilities to catalog" alert joins it.
const kevByDay = new Map();
for (const k of kevEntries) {
  if (!k.dateAdded || ageOf(k.dateAdded) > WINDOW_DAYS * DAY) continue;
  if (!kevByDay.has(k.dateAdded)) kevByDay.set(k.dateAdded, []);
  kevByDay.get(k.dateAdded).push(k);
}
const newKevCves = new Set([...kevByDay.values()].flat().map((k) => k.cve));
const kevSource = sources.find((s) => s.kind === 'kev');
const kevStories = [];
for (const [day, entries] of kevByDay) {
  const alertIdx = items.findIndex((i) => i.sourceId === 'cisa-advisories' && /known exploited vulnerabilit/i.test(i.title) && i.published.slice(0, 10) === day);
  const alert = alertIdx >= 0 ? items.splice(alertIdx, 1)[0] : null;
  const names = [...new Set(entries.map((e) => `${e.vendor} ${e.product}`))];
  const title = `CISA adds ${entries.length} exploited ${entries.length === 1 ? 'vulnerability' : 'vulnerabilities'} to KEV: ${names.slice(0, 3).join(', ')}${names.length > 3 ? ` and ${names.length - 3} more` : ''}`;
  const lead = {
    title, url: alert?.url || KEV_CATALOG, published: alert?.published || `${day}T12:00:00.000Z`,
    firstSeen: prevFirstSeen.get(alert?.url || KEV_CATALOG) || nowIso,
    excerpt: entries.map((e) => `${e.cve} (${e.vendor} ${e.product}): ${e.name}.`).join(' '),
    sourceId: 'cisa-kev', sourceName: alert ? 'CISA' : kevSource?.name || 'CISA KEV', sourceType: 'official', weight: kevSource?.weight ?? 1,
    kevGroup: day,
  };
  kevStories.push({ items: [lead], kev: entries });
}

// --- 3. group into stories ------------------------------------------------------

// Merges Claude found in earlier runs are applied first, so the same pair isn't re-sent every run.
const forced = new Map();
items.forEach((it) => { const g = mergedGroups.findIndex((s) => s.has(it.url)); if (g >= 0) forced.set(it, g); });
const byForced = new Map();
const stories = [];
for (const g of cluster(items)) {
  const fg = g.map((it) => forced.get(it)).find((x) => x !== undefined);
  if (fg !== undefined && byForced.has(fg)) { byForced.get(fg).items.push(...g); continue; }
  const st = { items: g };
  if (fg !== undefined) byForced.set(fg, st);
  stories.push(st);
}
stories.push(...kevStories);

function finish(st) {
  st.items.sort((a, b) => b.weight - a.weight || Date.parse(a.published) - Date.parse(b.published));
  const earliest = [...st.items].sort((a, b) => Date.parse(a.published) - Date.parse(b.published))[0];
  st.id = st.kev ? `kev-${st.items[0].kevGroup}` : storyId(earliest.url);
  st.key = contentKey(st);
  st.title = st.items[0].title;
  st.published = earliest.published;
  st.updated = st.items.reduce((m, i) => (i.published > m ? i.published : m), st.published);
  st.cves = st.kev ? st.kev.map((k) => k.cve) : cvesIn(st.items.map((i) => `${i.title} ${i.excerpt}`).join(' ')).slice(0, 12);
  st.inKev = !st.kev && st.cves.some((c) => newKevCves.has(c));
  st.deepDiveSource = st.items.some((i) => i.deepDiveSource);
  st.deepDiveGuess = st.items.some((i) => i.deepDive);
  return st;
}
stories.forEach(finish);
log(`${items.length} items → ${stories.length} stories`);

// --- 4. summarize with Claude (optional) -----------------------------------------

const claude = process.env.ANTHROPIC_API_KEY ? await import('./lib/summarize.mjs') : null;
const mergedUrls = mergedGroups.map((g) => [...g]).filter((g) => g.some((u) => seenUrls.has(normUrl(u))));
for (const st of stories) {
  const hit = summaryCache.get(st.key);
  if (hit) Object.assign(st, hit, { summarizedBy: 'claude' });
}
if (claude) {
  const pending = stories
    .filter((s) => !s.summarizedBy && ageOf(s.published) < (s.deepDiveGuess ? DEEP_DIVE_DAYS * 24 : SUMMARIZE_HOURS) * HOUR)
    .sort((a, b) => b.items[0].weight - a.items[0].weight || Date.parse(b.published) - Date.parse(a.published))
    .slice(0, SUMMARIZE_MAX);
  log(`Summarizing ${pending.length} new stories (${stories.filter((s) => s.summarizedBy).length} reused)…`);
  const res = await claude.summarize(pending, log);
  const byId = new Map(stories.map((s) => [s.id, s]));
  for (const [id, r] of res) Object.assign(byId.get(id), r, { summarizedBy: 'claude' });
  // Fold stories Claude identified as the same event into one.
  for (const [id, r] of res) {
    const target = r.sameStoryAs && byId.get(r.sameStoryAs);
    const st = byId.get(id);
    if (!target || target === st || st.merged || target.merged || st.kev || target.kev) continue;
    target.items.push(...st.items);
    st.merged = true;
    finish(target);
    mergedUrls.push(target.items.map((i) => i.url));
  }
} else {
  log('ANTHROPIC_API_KEY not set: using feed excerpts as summaries.');
}

function fallbackSummary(st) {
  if (st.kev) {
    const ransomware = st.kev.filter((k) => k.ransomware).length;
    return truncate(st.kev.map((k) => `${k.cve}: ${k.name} (${k.vendor} ${k.product}).`).join(' '), 420) +
      (ransomware ? ` ${ransomware} known to be used in ransomware campaigns.` : '');
  }
  const lead = st.items.find((i) => i.excerpt && i.excerpt.length > 40) || st.items[0];
  return truncate(lead.excerpt || '', 360);
}

const live = stories.filter((s) => !s.merged);
for (const st of live) {
  st.summary ||= fallbackSummary(st);
  st.whyItMatters ||= st.kev ? `US federal agencies must patch by ${st.kev[0].dueDate}; treat these as priority fixes everywhere.` : '';
  st.category ||= guessCategory(st);
  // A dedicated postmortem source always counts; otherwise Claude's judgement, or the headline when Claude isn't used.
  st.deepDive = st.deepDiveSource || (st.summarizedBy === 'claude' ? !!st.deepDive : st.deepDiveGuess);
  if (!st.deepDive && ageOf(st.published) > WINDOW_DAYS * DAY) st.dropped = true; // only kept for being a possible deep dive
}

// --- 4b. same event under different headlines --------------------------------------
// Grouping by headline misses coverage worded very differently ("SAP confirms cyber incident amid reports of source
// code breach" vs "SAP confirms security incident after suspicious GitHub activity"), and Claude only compares
// stories summarized in the same run. So stories within 36 hours that share a name and some wording are checked
// once by Claude; confirmed pairs are merged into one story, and the merge is remembered for later runs.
const DUP_HOURS = 36;
const DUP_CHECKS_MAX = 30;
if (claude) {
  const pool = live.filter((s) => !s.dropped && !s.kev && ageOf(s.published) < 72 * HOUR);
  const meta = new Map(pool.map((s) => [s, { names: properNames(s.title), toks: tokens(s.title) }]));
  const confirmed = [];
  const askDup = [];
  for (let i = 0; i < pool.length; i++) {
    for (let k = i + 1; k < pool.length; k++) {
      const a = pool[i], b = pool[k];
      if (Math.abs(Date.parse(a.published) - Date.parse(b.published)) > DUP_HOURS * HOUR) continue;
      const key = `dup|${[a.id, b.id].sort().join('|')}`;
      if (key in pairCache) { if (pairCache[key].f) confirmed.push([a, b]); continue; }
      const ma = meta.get(a), mb = meta.get(b);
      if (![...ma.names].some((n) => mb.names.has(n))) continue;
      const { inter, j } = jaccard(ma.toks, mb.toks);
      if (inter >= 2 && j >= 0.15 && askDup.length < DUP_CHECKS_MAX) askDup.push({ key, a, b });
    }
  }
  if (askDup.length) {
    log(`Checking ${askDup.length} possible duplicates…`);
    const brief = (st) => ({ title: st.title, summary: st.summary || '', date: st.published.slice(0, 10), source: st.items[0].sourceName });
    const res = await claude.sameEvent(askDup.map((p) => ({ pair: p.key, a: brief(p.a), b: brief(p.b) })), log);
    for (const p of askDup) {
      if (!res.has(p.key)) continue; // not answered: ask again next run
      pairCache[p.key] = { f: res.get(p.key) };
      if (res.get(p.key)) confirmed.push([p.a, p.b]);
    }
  }
  // Merge confirmed pairs (and chains of them) into the earliest story of each group.
  const parent = new Map();
  const find = (x) => { while (parent.get(x) !== x) x = parent.get(x); return x; };
  for (const [a, b] of confirmed) {
    if (!parent.has(a)) parent.set(a, a);
    if (!parent.has(b)) parent.set(b, b);
    parent.set(find(a), find(b));
  }
  const groups = new Map();
  for (const st of parent.keys()) { const r = find(st); if (!groups.has(r)) groups.set(r, []); groups.get(r).push(st); }
  let merges = 0;
  for (const group of groups.values()) {
    if (group.length < 2) continue;
    group.sort((x, y) => Date.parse(x.published) - Date.parse(y.published));
    const [target, ...rest] = group;
    for (const st of rest) {
      target.items.push(...st.items);
      st.merged = true;
      delete archive[st.id];
      merges++;
    }
    finish(target);
    mergedUrls.push(target.items.map((i) => i.url));
  }
  if (merges) log(`Merged ${merges} duplicate ${merges === 1 ? 'story' : 'stories'}`);
}

// --- 5. follow-ups: link new stories to earlier ones about the same incident --------

const current = live.filter((s) => !s.dropped && !s.merged).sort((a, b) => Date.parse(a.published) - Date.parse(b.published));
const recordOf = (st) => ({
  id: st.id,
  threadId: st.threadId,
  note: st.followUpNote || undefined,
  title: st.title,
  summary: truncate(st.summary, 300),
  category: st.category,
  importance: st.importance || undefined,
  published: st.published,
  updated: st.updated,
  cves: st.cves.length ? st.cves : undefined,
  deepDive: st.deepDive || undefined,
  source: st.items[0].sourceName,
  url: st.items[0].url,
});
const threadOf = (rec) => rec.threadId || rec.id;
const cveSet = (cves) => new Set(cves && cves.length <= 3 ? cves : []);

const toCheck = []; // { st, candidates: [{ rec, strong, sim }] }
for (const st of current) {
  const known = archive[st.id];
  if (st.kev) { st.threadId = st.id; continue; } // KEV batches span many unrelated products
  if (known?.checked) { st.threadId = known.threadId || st.id; st.followUpNote = known.note; continue; }
  st.threadId = st.id;
  const mine = cveSet(st.cves);
  const myTokens = tokens(st.title);
  const others = [...Object.values(archive), ...current.filter((c) => c !== st && c.threadId).map(recordOf)];
  const candidates = [];
  const seen = new Set();
  for (const rec of others) {
    if (rec.id === st.id || seen.has(rec.id) || rec.id.startsWith('kev-')) continue;
    seen.add(rec.id);
    // A follow-up comes at least most of a day after the original; same-day coverage is grouped already.
    if (Date.parse(rec.published) > Date.parse(st.published) - 20 * HOUR) continue;
    if (ageOf(rec.published) > ARCHIVE_DAYS * DAY) continue;
    const sharedCve = [...cveSet(rec.cves)].some((c) => mine.has(c));
    const { inter, j } = jaccard(myTokens, tokens(rec.title));
    if (sharedCve || j >= 0.25 && inter >= 2) candidates.push({ rec, strong: sharedCve || j >= 0.5, sim: j + (sharedCve ? 1 : 0) });
  }
  candidates.sort((a, b) => b.sim - a.sim);
  if (candidates.length) toCheck.push({ st, candidates: candidates.slice(0, 3) });
  else st.checked = true;
}

let followUps = 0;
if (toCheck.length) {
  const decisions = new Map(); // pairKey -> { f, n }
  for (const [k, v] of Object.entries(pairCache)) decisions.set(k, v);
  if (claude) {
    const ask = [];
    for (const { st, candidates } of toCheck) {
      for (const c of candidates) {
        const pair = `${st.id}|${c.rec.id}`;
        if (!decisions.has(pair) && ask.length < FOLLOWUP_CHECKS_MAX) {
          ask.push({
            pair,
            earlier: { title: c.rec.title, summary: c.rec.summary || '', date: c.rec.published.slice(0, 10) },
            later: { title: st.title, summary: st.summary, date: st.published.slice(0, 10) },
          });
        }
      }
    }
    if (ask.length) {
      log(`Checking ${ask.length} possible follow-ups…`);
      const res = await claude.confirmFollowUps(ask, log);
      for (const [pair, r] of res) decisions.set(pair, { f: r.followUp, n: r.note });
    }
  }
  for (const { st, candidates } of toCheck) {
    let decided = true;
    let match = null;
    for (const c of candidates) {
      const d = decisions.get(`${st.id}|${c.rec.id}`);
      if (d) { pairCache[`${st.id}|${c.rec.id}`] = d; if (d.f && !match) match = { c, note: d.n }; continue; }
      if (!claude) { if (c.strong && !match) match = { c, note: '' }; continue; }
      decided = false; // not checked yet (over this run's limit): try again next run
    }
    if (match) {
      st.threadId = threadOf(match.c.rec);
      st.followUpNote = match.note || undefined;
      followUps++;
    }
    st.checked = decided || !!match;
  }
}
log(`Follow-ups: ${followUps} new links (${toCheck.length} stories had candidates)`);

// Update the archive with this run's stories, then drop what is too old.
for (const st of current) archive[st.id] = { ...recordOf(st), checked: st.checked ?? archive[st.id]?.checked ?? true };
for (const [id, rec] of Object.entries(archive)) if (ageOf(rec.updated || rec.published) > ARCHIVE_DAYS * DAY) delete archive[id];
const archiveIds = Object.keys(archive).sort((a, b) => Date.parse(archive[b].published) - Date.parse(archive[a].published));
for (const id of archiveIds.slice(3000)) delete archive[id];

// One card per thread: the newest story carries the earlier ones as its timeline.
const byThread = new Map();
for (const rec of Object.values(archive)) {
  const t = threadOf(rec);
  if (!byThread.has(t)) byThread.set(t, []);
  byThread.get(t).push(rec);
}
for (const st of current) {
  const members = (byThread.get(st.threadId) || []).filter((r) => r.id !== st.id);
  const later = members.some((r) => Date.parse(r.published) > Date.parse(st.published) && current.some((c) => c.id === r.id));
  if (later) { st.hiddenInThread = true; continue; }
  st.timeline = members
    .filter((r) => Date.parse(r.published) <= Date.parse(st.published))
    .sort((a, b) => Date.parse(a.published) - Date.parse(b.published))
    .map((r) => ({ id: r.id, title: r.title, date: r.published, source: r.source, url: r.url, note: r.note }));
}

// --- 6. CVE details ----------------------------------------------------------------

const shown = current.filter((s) => !s.hiddenInThread);
const allCves = [...new Set(shown.flatMap((s) => s.cves))];
if (allCves.length) {
  log(`Looking up ${allCves.length} CVEs…`);
  await enrichCves(allCves, cveCache, log);
}
const archivedCves = new Set(Object.values(archive).flatMap((r) => r.cves || []));
for (const id of Object.keys(cveCache)) if (!archivedCves.has(id) && !allCves.includes(id)) delete cveCache[id];

// --- 7. rank and output --------------------------------------------------------------

for (const st of shown) {
  st.base = baseScore(st) + (st.inKev ? 8 : 0) + (st.timeline?.length ? 5 : 0);
  const exploited = st.cves.some((c) => cveCache[c]?.exploitation === 'active' || (cveCache[c]?.epss ?? 0) >= 0.5);
  st.exploitedCve = exploited;
  if (exploited && !st.kev) st.base += 4;
}

/** Plain-language reasons a story ranks where it does, for the app's story page. */
function rankingReasons(st) {
  const r = [];
  if (st.importance) r.push(`Rated ${st.importance}/5 for importance by Claude`);
  const n = new Set(st.items.map((i) => i.sourceName)).size;
  if (n > 1) r.push(`Covered by ${n} sources`);
  if (st.kev) r.push('Newly added to CISA’s Known Exploited Vulnerabilities list');
  else if (st.inKev) r.push('Its CVE is on CISA’s Known Exploited Vulnerabilities list');
  if (!st.kev && (st.exploitedCve || st.category === 'Exploited vulnerability')) r.push('Being exploited in attacks');
  if (st.cves.some((c) => (cveCache[c]?.cvss ?? 0) >= 9)) r.push('Critical CVSS severity (9.0+)');
  if (st.timeline?.length) r.push(`Development in a story first reported ${new Date(st.timeline[0].date).toISOString().slice(0, 10)}`);
  if (st.items.some((i) => i.sourceType === 'official')) r.push('Reported by an official agency');
  if (st.deepDive) r.push('Postmortem or in-depth investigation');
  return r.slice(0, 6);
}

function toOutput(st) {
  const out = {
    id: st.id,
    key: contentKey(st),
    title: st.title,
    summary: st.summary,
    whyItMatters: st.whyItMatters,
    category: st.category,
    importance: st.importance || null,
    deepDive: st.deepDive || undefined,
    summarizedBy: st.summarizedBy || 'feed',
    score: finalScore(st, now),
    published: st.published,
    updated: st.updated,
    cves: st.cves,
    inKev: st.inKev || undefined,
    sources: st.items.map((i) => ({ name: i.sourceName, type: i.sourceType, title: i.title, url: i.url, published: i.published, firstSeen: i.firstSeen })),
  };
  if (st.timeline?.length) { out.timeline = st.timeline; out.followUpNote = st.followUpNote; }
  const cveInfo = {};
  for (const c of st.cves) {
    const d = cveCache[c];
    if (d && !d.missing) cveInfo[c] = { cvss: d.cvss, severity: d.severity, epss: d.epss, epssPercentile: d.epssPercentile, exploitation: d.exploitation, title: d.title };
  }
  if (Object.keys(cveInfo).length) out.cveInfo = cveInfo;
  out.reasons = rankingReasons(st);
  if (st.kev) out.kev = st.kev.map((k) => ({ cve: k.cve, vendor: k.vendor, product: k.product, name: k.name, dueDate: k.dueDate, ransomware: k.ransomware }));
  return out;
}

const ranked = shown.map(toOutput).sort((a, b) => b.score - a.score);
const final = ranked.filter((s, i) => i < MAX_STORIES || s.deepDive);

// The week's most important stories, by importance rather than freshness.
const weekScore = (st) => (st.importance ? st.base * 0.4 + st.importance * 14 : st.base);
const weekTop = shown
  .filter((s) => ageOf(s.published) <= 7 * DAY && final.some((f) => f.id === s.id))
  .sort((a, b) => weekScore(b) - weekScore(a))
  .slice(0, 10);
let recap = state.recap || null;
if (claude && weekTop.length >= 3 && (!recap || ageOf(recap.generatedAt) > RECAP_EVERY_HOURS * HOUR)) {
  log('Writing weekly recap…');
  const text = await claude.weeklyRecap(weekTop, log);
  if (text) recap = { text, generatedAt: nowIso };
}
if (!claude) recap = null;

// The Daily Brief: the day's top stories grouped by topic, built once a day when the digest is due
// (or once per day when no DIGEST is set) and then kept fixed until the next one.
const DAILY_SIZE = 8;
const schedule = dailySchedule(log);
let daily = state.daily || null;
const dailyGone = daily && !daily.storyIds.some((id) => final.some((f) => f.id === id));
const needDaily = !daily || dailyGone ||
  (schedule.due ? !(daily.scheduled && daily.date === schedule.due) : !schedule.configured && daily.date !== schedule.today);
if (needDaily) {
  const within = (h) => shown.filter((s) => ageOf(s.published) <= h * HOUR && final.some((f) => f.id === s.id));
  let pool = within(24);
  if (pool.length < 5) pool = within(48);
  const picks = pool.sort((a, b) => weekScore(b) - weekScore(a)).slice(0, DAILY_SIZE);
  if (picks.length) {
    log(`Building Daily Brief (${picks.length} stories)…`);
    let brief = claude ? await claude.dailyBrief(picks, log) : null;
    if (!brief) {
      // Without Claude: one topic per category, in order of each category's most important story.
      const byCat = new Map();
      for (const st of picks) { if (!byCat.has(st.category)) byCat.set(st.category, []); byCat.get(st.category).push(st.id); }
      brief = { overview: null, topics: [...byCat].map(([label, storyIds]) => ({ label, summary: '', storyIds })) };
    }
    daily = {
      date: schedule.due || schedule.today,
      scheduled: !!schedule.due,
      generatedAt: nowIso,
      overview: brief.overview,
      topics: brief.topics,
      storyIds: brief.topics.flatMap((t) => t.storyIds),
    };
  }
}

// --- 8. push alerts (optional) ---------------------------------------------------------

const alerted = state.alerted || {}; // story id -> when it alerted
let alertState = state.alertState || null;
if (process.env.NTFY_TOPIC) {
  log('Alerts…');
  const outById = new Map(final.map((o) => [o.id, o]));
  const ctx = { terms: watchTerms(), archive, cveCache };
  const candidates = [];
  for (const st of shown) {
    const out = outById.get(st.id);
    const reason = out && alertReason(st, out, ctx);
    if (reason) candidates.push({ out, reason });
  }
  alertState = await sendAlerts({ candidates, alerted, alertState, appUrl: process.env.APP_URL, builtAt: nowIso, log });
}
for (const [id, at] of Object.entries(alerted)) if (ageOf(at) > ARCHIVE_DAYS * DAY) delete alerted[id];

// Health: alert when sources keep failing or Claude stops working; the app shows it too.
const healthState = state.health || {};
const health = await checkHealth({ health: healthState, status, claudeStats: claude?.claudeStats, appUrl: process.env.APP_URL, log });
const digestState = await sendDigest({ daily, due: schedule.due, digestState: state.digest, appUrl: process.env.APP_URL, builtAt: nowIso, log });

if (claude) {
  const u = claude.claudeUsage;
  log(`Claude (${claude.summarizerModel}): ${u.input} input + ${u.output} output tokens this run`);
}

const briefing = {
  version: 2,
  generatedAt: nowIso,
  summarizer: claude ? 'claude' : 'feed',
  updateEveryHours: 1, // keep in step with the cron schedule in .github/workflows/briefing.yml
  repo: process.env.GITHUB_REPOSITORY || null,
  sources: status.sort((a, b) => a.id.localeCompare(b.id)),
  daily,
  week: { storyIds: weekTop.map((s) => s.id), recap: recap?.text || null, recapAt: recap?.generatedAt || null },
  health,
  stories: final,
};

// Keep only cached follow-up decisions that still involve archived stories.
for (const k of Object.keys(pairCache)) {
  const [a, b] = k.startsWith('dup|') ? k.slice(4).split('|') : k.split('|');
  if (!archive[a] || !archive[b]) delete pairCache[k];
}
const newState = { version: 1, savedAt: nowIso, archive, cves: cveCache, pairs: pairCache, mergedUrls: mergedUrls.slice(-300), recap, alerted, alertState, health: healthState, digest: digestState, daily };

await mkdir(OUT_DIR, { recursive: true });
await writeFile(new URL('briefing.json', OUT_DIR), JSON.stringify(briefing));
await writeFile(new URL('state.json', OUT_DIR), JSON.stringify(newState));
log(`Wrote ${final.length} stories (${final.filter((s) => s.deepDive).length} deep dives, ${final.filter((s) => s.timeline).length} with timelines); archive holds ${Object.keys(archive).length}`);
for (const s of final.slice(0, 10)) log(`  ${String(s.score).padStart(5)}  [${s.category}] ${s.title} (${s.sources.length} src${s.timeline ? `, update to ${s.timeline.length}` : ''})`);
