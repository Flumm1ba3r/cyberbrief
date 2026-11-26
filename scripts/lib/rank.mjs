// Turning raw feed items into ranked stories: filter noise, group coverage of the same event, score.
import { createHash } from 'node:crypto';

const HOUR = 3600 * 1000;

// Items that are not news: promos, podcasts, recurring columns.
const NOISE = [
  /\bsponsored\b/i, /\bwebinar\b/i, /\bpodcast\b/i, /\bnewsletter\b/i, /\bstormcast\b/i,
  /\bsquid blogging\b/i, /\bweek in review\b/i, /\bweekly (recap|roundup|update)\b/i,
  /\b(deal|deals|discount|coupon)s?\b.*\b(off|save|price)\b/i, /\bbest .{0,40}\b(of 20\d\d|to buy)\b/i,
  /\b(live|virtual) event\b/i, /^\s*(video|watch):/i, /\bupcoming speaking engagements\b/i,
];
export const isNoise = (item) => NOISE.some((re) => re.test(item.title));

const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
export const cvesIn = (text) => [...new Set((text.match(CVE_RE) || []).map((c) => c.toUpperCase()))];

const STOP = new Set(('a an and are as at be by can could for from has have how in into is it its of on or that the their this to ' +
  'was were what when which who will with after over new says said report reports researchers security cyber attack attacks ' +
  'hackers hacker update updates warns warning more than about amid just now why your you our we us out up via vs').split(' '));

export function tokens(title) {
  return new Set(
    title.toLowerCase()
      .replace(/[’']s\b/g, '')
      .split(/[^a-z0-9.-]+/)
      .map((w) => w.replace(/^[.-]+|[.-]+$/g, ''))
      .filter((w) => w.length >= 3 && !STOP.has(w)),
  );
}

export function jaccard(a, b) {
  let inter = 0;
  for (const t of a) if (b.has(t)) inter++;
  return { inter, j: inter / (a.size + b.size - inter || 1) };
}

/** Group items that cover the same event (shared CVE or very similar headline, within 4 days). */
export function cluster(items) {
  const parent = items.map((_, i) => i);
  const find = (i) => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  const union = (a, b) => { parent[find(a)] = find(b); };

  const meta = items.map((it) => ({
    toks: tokens(it.title),
    cves: new Set(it.kevGroup ? [] : cvesIn(`${it.title} ${it.excerpt}`)),
    t: Date.parse(it.published || 0),
  }));

  for (let i = 0; i < items.length; i++) {
    for (let k = i + 1; k < items.length; k++) {
      if (items[i].sourceId === items[k].sourceId) continue;
      if (items[i].kevGroup || items[k].kevGroup) continue;
      if (Math.abs(meta[i].t - meta[k].t) > 96 * HOUR) continue;
      const sharedCve = [...meta[i].cves].some((c) => meta[k].cves.has(c));
      // A shared CVE only counts when the item isn't a multi-CVE roundup.
      const cveMatch = sharedCve && meta[i].cves.size <= 3 && meta[k].cves.size <= 3;
      const { inter, j } = jaccard(meta[i].toks, meta[k].toks);
      if (cveMatch || j >= 0.42 || (inter >= 4 && j >= 0.3)) union(i, k);
    }
  }

  const groups = new Map();
  items.forEach((it, i) => {
    const r = find(i);
    if (!groups.has(r)) groups.set(r, []);
    groups.get(r).push(it);
  });
  return [...groups.values()];
}

// Postmortems, root-cause analyses, incident write-ups and other long-form retrospectives.
const DEEP_DIVE = /\bpost[- ]?mortem\b|\bpost[- ]incident\b|\broot[- ]cause\b|\bincident (report|review|analysis)\b|\bfinal report\b|\bafter[- ]action\b|\blessons learned\b|\bretrospective\b|\bwhat (went wrong|happened)\b|\b(inside|anatomy of|timeline of|deep dive|a look back)\b|\bavailability report\b|\bcase study\b|\binvestigation (into|of)\b|\breport (finds|reveals|details)\b/i;
export const looksLikeDeepDive = (title) => DEEP_DIVE.test(title);

// --- scoring ------------------------------------------------------------------

const BOOSTS = [
  [/\b(actively|being|under active|widely|mass(ively)?) exploit|exploited in the wild|in-the-wild|zero[- ]day|0[- ]day\b/i, 12],
  [/\bemergency directive\b|\bpatch (now|immediately)\b|\burgent(ly)?\b|\bout[- ]of[- ]band\b/i, 8],
  [/\bransomware\b|\bextortion\b/i, 6],
  [/\bsupply[- ]chain\b|\bbackdoor(ed)?\b|\bmalicious (packages?|update)\b/i, 6],
  [/\b(data )?breach(es|ed)?\b|\bleak(ed|s)?\b|\bstolen\b|\bexposed\b|\bhacked\b/i, 5],
  [/\bnation[- ]state\b|\bstate[- ]sponsored\b|\bAPT\s?\d*\b|\bespionage\b|\bVolt Typhoon\b|\bSalt Typhoon\b|\bLazarus\b/i, 5],
  [/\bcritical\b|\bCVSS (score of )?(9|10)(\.\d)?\b|\bremote code execution\b|\bRCE\b|\bunauthenticated\b/i, 4],
  [/\bbotnet\b|\bwiper\b|\bDDoS\b|\bspyware\b|\bstealer\b/i, 3],
  [/\barrest(ed)?\b|\bindict(ed|ment)\b|\bsanction(s|ed)\b|\btakedown\b|\bseized?\b|\bcharged\b/i, 3],
];
const PENALTIES = [
  [/\bhow to\b|\bwhat is\b|\bexplained\b|\bguide\b|\btips\b|\bbest practices\b|\bopinion\b|\binterview\b|\bQ&A\b/i, -8],
  [/\bfunding\b|\braises \$|\bacquires?\b|\bacquisition\b|\bIPO\b|\bappoints?\b|\bhires?\b|\bpartnership\b/i, -6],
  [/\b(product|feature) (launch|release)\b|\bannounces? (new|general availability)\b/i, -5],
];

/** Heuristic importance before recency, roughly 0-100. */
export function baseScore(story) {
  const text = `${story.title} ${story.items.map((i) => i.excerpt).join(' ').slice(0, 1500)}`;
  const distinctSources = new Set(story.items.map((i) => i.sourceName)).size;
  let s = 25 * Math.max(...story.items.map((i) => i.weight));
  s += Math.min(30, 7 * (distinctSources - 1));
  for (const [re, pts] of BOOSTS) if (re.test(text)) s += pts;
  for (const [re, pts] of PENALTIES) if (re.test(story.title)) s += pts;
  if (story.items.some((i) => i.sourceType === 'official')) s += 3;
  if (story.cves.length) s += 2;
  if (story.kev) s += 14 + Math.min(10, 2 * story.kev.length) + (story.kev.some((k) => k.ransomware) ? 4 : 0);
  return s;
}

/** Final ranking score: importance (heuristic, plus Claude's 1-5 rating when present) decayed by age. */
export function finalScore(story, now) {
  const ageH = Math.max(0, (now - Date.parse(story.published)) / HOUR);
  const importance = story.importance ? story.base * 0.4 + story.importance * 14 : story.base;
  return Math.round(importance * Math.pow(0.5, ageH / 30) * 10) / 10;
}

// --- categories (used when Claude is not available) -------------------------

export const CATEGORIES = ['Exploited vulnerability', 'Vulnerability', 'Ransomware', 'Breach', 'Threat actor', 'Malware', 'Law & policy', 'Privacy', 'Advisory', 'Industry'];

export function guessCategory(story) {
  const t = `${story.title} ${story.items[0]?.excerpt || ''}`;
  if (story.kev || /\b(actively|being) exploited|exploited in the wild|zero[- ]day|0[- ]day/i.test(t)) return 'Exploited vulnerability';
  if (/\bransomware\b|\bextortion\b/i.test(t)) return 'Ransomware';
  if (/\bbreach|\bleak(ed)?\b|\bstolen data\b|\bexposed\b.*\b(records|data)\b|\bhacked\b/i.test(t)) return 'Breach';
  if (/\bnation[- ]state\b|\bstate[- ]sponsored\b|\bAPT\s?\d*\b|\bespionage\b|\bTyphoon\b|\bthreat actors?\b|\bgroup\b.*\btarget/i.test(t)) return 'Threat actor';
  if (/\bmalware\b|\bbotnet\b|\bstealer\b|\btrojan\b|\bspyware\b|\bwiper\b|\bloader\b|\bphishing\b/i.test(t)) return 'Malware';
  if (/\bCVE-\d|\bvulnerabilit|\bflaw\b|\bpatch(es|ed)?\b|\bbug\b|\bsecurity update/i.test(t)) return 'Vulnerability';
  if (/\barrest|\bindict|\bsanction|\blaw\b|\bregulat|\bcourt\b|\bcongress\b|\bparliament\b|\bpolicy\b|\bcharged\b|\bsentenced\b/i.test(t)) return 'Law & policy';
  if (/\bprivacy\b|\bsurveillance\b|\btracking\b/i.test(t)) return 'Privacy';
  if (story.items.every((i) => i.sourceType === 'official')) return 'Advisory';
  return 'Industry';
}

export const storyId = (url) => createHash('sha256').update(url).digest('hex').slice(0, 12);
export const contentKey = (story) =>
  createHash('sha256').update(story.items.map((i) => i.url).sort().join('\n')).digest('hex').slice(0, 12);
