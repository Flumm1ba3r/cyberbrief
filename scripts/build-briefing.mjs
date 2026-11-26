// Builds site/data/briefing.json: fetch every source, group coverage of the same event, rank, summarize.
// Run by .github/workflows/briefing.yml on a schedule. Locally: `npm run build` (needs network access to the feeds),
// or offline with CYBERBRIEF_FIXTURES=<dir of <source-id>.xml files>.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { loadSource, truncate } from './lib/feeds.mjs';
import { isNoise, cvesIn, cluster, baseScore, finalScore, guessCategory, storyId, contentKey } from './lib/rank.mjs';

const ROOT = new URL('../', import.meta.url);
const OUT_DIR = new URL('site/data/', ROOT);
const OUT_FILE = new URL('briefing.json', OUT_DIR);

const HOUR = 3600 * 1000;
const WINDOW_DAYS = 7; // stories older than this are dropped
const SUMMARIZE_HOURS = 72; // only recent stories are sent to Claude
const SUMMARIZE_MAX = 45; // ...and at most this many per run
const MAX_STORIES = 250;
const KEV_CATALOG = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog';

const log = (...a) => console.log(...a);
const now = Date.now();

async function pool(items, n, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: n }, async () => {
    while (next < items.length) { const i = next++; out[i] = await fn(items[i], i); }
  }));
  return out;
}

async function loadPrevious() {
  const url = process.env.PREVIOUS_URL;
  try {
    if (url) {
      const res = await fetch(url, { headers: { 'Cache-Control': 'no-cache' } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    }
    return JSON.parse(await readFile(OUT_FILE, 'utf8'));
  } catch (e) {
    log(`No previous briefing (${url || 'local file'}): ${e.message}`);
    return null;
  }
}

// --- 1. fetch ---------------------------------------------------------------

const { sources } = JSON.parse(await readFile(new URL('sources.json', ROOT), 'utf8'));
const previous = await loadPrevious();
const prevFirstSeen = new Map();
const cache = new Map(); // contentKey -> Claude's result from an earlier run
for (const s of previous?.stories || []) {
  for (const src of s.sources) prevFirstSeen.set(src.url, src.firstSeen || src.published);
  if (s.summarizedBy === 'claude') {
    cache.set(s.key, { summary: s.summary, whyItMatters: s.whyItMatters, importance: s.importance, category: s.category });
  }
}
const mergedGroups = (previous?.mergedUrls || []).map((g) => new Set(g));

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

const cutoff = now - WINDOW_DAYS * 24 * HOUR;
const seenUrls = new Set();
const items = [];
let kevEntries = [];

for (const { src, items: raw } of results) {
  if (src.kind === 'kev') { kevEntries = raw; continue; }
  for (const it of raw) {
    const key = it.url.replace(/[?#].*$/, '').replace(/\/$/, '');
    if (seenUrls.has(key)) continue;
    seenUrls.add(key);
    const firstSeen = prevFirstSeen.get(it.url) || new Date(now).toISOString();
    // Undated items, or dates in the future, fall back to when CyberBrief first saw them.
    let published = it.published && Date.parse(it.published) <= now + HOUR ? it.published : firstSeen;
    if (Date.parse(published) < cutoff || isNoise(it)) continue;
    items.push({ ...it, published, firstSeen, sourceId: src.id, sourceName: src.name, sourceType: src.type, weight: src.weight });
  }
}

// CISA KEV: one story per day entries were added. CISA's own "adds N vulnerabilities to catalog" alert joins it.
const kevByDay = new Map();
for (const k of kevEntries) {
  if (!k.dateAdded || Date.parse(k.dateAdded) < cutoff) continue;
  if (!kevByDay.has(k.dateAdded)) kevByDay.set(k.dateAdded, []);
  kevByDay.get(k.dateAdded).push(k);
}
const newKevCves = new Set(kevEntries.filter((k) => Date.parse(k.dateAdded) >= cutoff).map((k) => k.cve));
const kevSource = sources.find((s) => s.kind === 'kev');
const kevStories = [];
for (const [day, entries] of kevByDay) {
  const alertIdx = items.findIndex((i) => i.sourceId === 'cisa-advisories' && /known exploited vulnerabilit/i.test(i.title) && i.published.slice(0, 10) === day);
  const alert = alertIdx >= 0 ? items.splice(alertIdx, 1)[0] : null;
  const names = [...new Set(entries.map((e) => `${e.vendor} ${e.product}`))];
  const title = `CISA adds ${entries.length} exploited ${entries.length === 1 ? 'vulnerability' : 'vulnerabilities'} to KEV: ${names.slice(0, 3).join(', ')}${names.length > 3 ? ` and ${names.length - 3} more` : ''}`;
  const lead = {
    title, url: alert?.url || KEV_CATALOG, published: alert?.published || `${day}T12:00:00.000Z`,
    firstSeen: prevFirstSeen.get(alert?.url || KEV_CATALOG) || new Date(now).toISOString(),
    excerpt: entries.map((e) => `${e.cve} (${e.vendor} ${e.product}): ${e.name}.`).join(' '),
    sourceId: 'cisa-kev', sourceName: alert ? 'CISA' : kevSource?.name || 'CISA KEV', sourceType: 'official', weight: kevSource?.weight ?? 1,
    kevGroup: day,
  };
  kevStories.push({ items: [lead], kev: entries });
}

// --- 3. group into stories ------------------------------------------------------

// Merges Claude found in earlier runs are applied first, so the same pair isn't re-sent every run.
const forced = new Map();
items.forEach((it, i) => { const g = mergedGroups.findIndex((s) => s.has(it.url)); if (g >= 0) forced.set(i, g); });
const groups = cluster(items);
const byForced = new Map();
const stories = [];
for (const g of groups) {
  const fg = g.map((it) => forced.get(items.indexOf(it))).find((x) => x !== undefined);
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
  st.base = baseScore(st) + (st.inKev ? 8 : 0);
  return st;
}
stories.forEach(finish);
log(`${items.length} items → ${stories.length} stories`);

// --- 4. summarize with Claude (optional) -----------------------------------------

const mergedUrls = mergedGroups.map((g) => [...g]).filter((g) => g.some((u) => seenUrls.has(u.replace(/[?#].*$/, '').replace(/\/$/, ''))));
let summarizerModel = null;
for (const st of stories) {
  const hit = cache.get(st.key);
  if (hit) Object.assign(st, hit, { summarizedBy: 'claude' });
}
if (process.env.ANTHROPIC_API_KEY) {
  const { summarize, summarizerModel: model } = await import('./lib/summarize.mjs');
  summarizerModel = model;
  const pending = stories
    .filter((s) => !s.summarizedBy && now - Date.parse(s.published) < SUMMARIZE_HOURS * HOUR)
    .sort((a, b) => finalScore(b, now) - finalScore(a, now))
    .slice(0, SUMMARIZE_MAX);
  log(`Summarizing ${pending.length} new stories (${stories.filter((s) => s.summarizedBy).length} reused)…`);
  const res = await summarize(pending, log);
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

// --- 5. output ------------------------------------------------------------------

function fallbackSummary(st) {
  if (st.kev) {
    const ransomware = st.kev.filter((k) => k.ransomware).length;
    return truncate(st.kev.map((k) => `${k.cve}: ${k.name} (${k.vendor} ${k.product}).`).join(' '), 420) +
      (ransomware ? ` ${ransomware} known to be used in ransomware campaigns.` : '');
  }
  const lead = st.items.find((i) => i.excerpt && i.excerpt.length > 40) || st.items[0];
  return truncate(lead.excerpt || '', 360);
}

const final = stories
  .filter((s) => !s.merged)
  .map((st) => {
    // A merged story's cached Claude summary must cover the final set of items, so refresh its key.
    st.key = contentKey(st);
    const out = {
      id: st.id,
      key: st.key,
      title: st.title,
      summary: st.summary || fallbackSummary(st),
      whyItMatters: st.whyItMatters || (st.kev ? `US federal agencies must patch by ${st.kev[0].dueDate}; treat these as priority fixes everywhere.` : ''),
      category: st.category || guessCategory(st),
      importance: st.importance || null,
      summarizedBy: st.summarizedBy || 'feed',
      score: finalScore(st, now),
      published: st.published,
      updated: st.updated,
      cves: st.cves,
      inKev: st.inKev || undefined,
      sources: st.items.map((i) => ({ name: i.sourceName, type: i.sourceType, title: i.title, url: i.url, published: i.published, firstSeen: i.firstSeen })),
    };
    if (st.kev) out.kev = st.kev.map((k) => ({ cve: k.cve, vendor: k.vendor, product: k.product, name: k.name, dueDate: k.dueDate, ransomware: k.ransomware }));
    return out;
  })
  .sort((a, b) => b.score - a.score)
  .slice(0, MAX_STORIES);

const briefing = {
  version: 1,
  generatedAt: new Date(now).toISOString(),
  summarizer: summarizerModel ? 'claude' : 'feed',
  updateEveryHours: 2, // keep in step with the cron schedule in .github/workflows/briefing.yml
  repo: process.env.GITHUB_REPOSITORY || null,
  sources: status.sort((a, b) => a.id.localeCompare(b.id)),
  stories: final,
  mergedUrls: mergedUrls.slice(-300),
};

await mkdir(OUT_DIR, { recursive: true });
await writeFile(OUT_FILE, JSON.stringify(briefing));
log(`Wrote ${final.length} stories to site/data/briefing.json`);
for (const s of final.slice(0, 10)) log(`  ${String(s.score).padStart(5)}  [${s.category}] ${s.title} (${s.sources.length} src)`);
