// CVE details: severity from the official CVE record (cvelistV5 on GitHub) and exploit likelihood from FIRST's EPSS.
import { USER_AGENT } from './feeds.mjs';

const RECORD_URL = (id) => {
  const [, year, num] = id.split('-');
  return `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${year}/${num.slice(0, -3)}xxx/${id}.json`;
};
const EPSS_URL = 'https://api.first.org/data/v1/epss?cve=';
const REFRESH_MS = 24 * 3600 * 1000; // scores change as vendors and CISA enrich records
const MISSING_RETRY_MS = 6 * 3600 * 1000; // brand-new CVEs often have no published record yet

async function getJson(url) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 15000);
  try {
    const res = await fetch(url, { headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' }, signal: ctrl.signal });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

/** Pick the most useful CVSS score from a CVE record: CVSS 3.1, then 4.0, then 3.0, from the CNA or CISA's enrichment. */
export function parseRecord(j) {
  const containers = [j.containers?.cna, ...(j.containers?.adp || [])].filter(Boolean);
  let best = null;
  const rank = { cvssV3_1: 3, cvssV4_0: 2, cvssV3_0: 1 };
  let exploitation = null;
  for (const c of containers) {
    for (const m of c.metrics || []) {
      for (const [k, r] of Object.entries(rank)) {
        const v = m[k];
        if (v && typeof v.baseScore === 'number' && (!best || r > best.r)) {
          best = { r, score: v.baseScore, severity: (v.baseSeverity || '').toLowerCase(), version: k.replace('cvssV', '').replace('_', '.') };
        }
      }
      if (m.other?.type === 'ssvc') {
        const opt = (m.other.content?.options || []).find((o) => o.Exploitation);
        if (opt) exploitation = opt.Exploitation; // none | poc | active
      }
    }
  }
  return {
    cvss: best?.score ?? null,
    severity: best?.severity || null,
    cvssVersion: best?.version || null,
    exploitation,
    title: (j.containers?.cna?.title || '').slice(0, 160) || null,
  };
}

/**
 * Fill `cache` (CVE id -> details) for the given ids, fetching only what is missing or stale.
 * Never throws: CVE details are a nice-to-have.
 */
export async function enrichCves(ids, cache, log) {
  const now = Date.now();
  const stale = ids.filter((id) => {
    const c = cache[id];
    if (!c) return true;
    return now - Date.parse(c.fetchedAt) > (c.missing ? MISSING_RETRY_MS : REFRESH_MS);
  }).slice(0, 250);
  if (!stale.length) return;

  let records = 0;
  let next = 0;
  await Promise.all(Array.from({ length: 6 }, async () => {
    while (next < stale.length) {
      const id = stale[next++];
      try {
        const j = await getJson(RECORD_URL(id));
        const prev = cache[id] || {};
        cache[id] = j
          ? { ...prev, ...parseRecord(j), missing: undefined, fetchedAt: new Date(now).toISOString() }
          : { ...prev, missing: true, fetchedAt: new Date(now).toISOString() };
        if (j) records++;
      } catch (e) {
        log(`  CVE record ${id}: ${e.message}`);
      }
    }
  }));

  let epssCount = 0;
  for (let i = 0; i < stale.length; i += 80) {
    const batch = stale.slice(i, i + 80);
    try {
      const j = await getJson(EPSS_URL + batch.join(','));
      for (const row of j?.data || []) {
        if (!cache[row.cve]) continue;
        cache[row.cve].epss = Math.round(parseFloat(row.epss) * 1000) / 1000;
        cache[row.cve].epssPercentile = Math.round(parseFloat(row.percentile) * 100) / 100;
        epssCount++;
      }
    } catch (e) {
      log(`  EPSS: ${e.message}`);
    }
  }
  log(`  CVE details: ${records}/${stale.length} records, ${epssCount} EPSS scores`);
}
