// One-off feed check: run in GitHub Actions to see which feeds work from GitHub's servers.
// Dependency-free (Node >= 20). Writes feedcheck-results/results.json and results.md.
import { readFile, writeFile, mkdir, appendFile } from 'node:fs/promises';

const UA = 'CyberBrief/0.1 (personal security-news reader; feed check)';
const TIMEOUT_MS = 15000;
const CONCURRENCY = 4;

const { sources } = JSON.parse(await readFile(new URL('./candidates.json', import.meta.url), 'utf8'));

async function get(url) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  const started = Date.now();
  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': UA, Accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml, application/json, text/html;q=0.8, */*;q=0.5' },
      redirect: 'follow',
      signal: ctrl.signal,
    });
    const body = await res.text();
    return {
      ok: res.ok, status: res.status, finalUrl: res.url, ms: Date.now() - started,
      contentType: res.headers.get('content-type') || '',
      etag: !!res.headers.get('etag'), lastModified: !!res.headers.get('last-modified'),
      body,
    };
  } catch (e) {
    return { ok: false, status: 0, error: e.name === 'AbortError' ? 'timeout' : String(e.cause?.code || e.message), ms: Date.now() - started };
  } finally {
    clearTimeout(t);
  }
}

function attr(tag, name) {
  const m = tag.match(new RegExp(`${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
  return m ? (m[2] ?? m[3] ?? m[4]) : null;
}
const decode = (s) => s.replace(/&amp;/g, '&').replace(/&#x2F;/gi, '/').replace(/&#47;/g, '/');

function discoverFeeds(html, base) {
  const out = [];
  for (const tag of html.match(/<link\b[^>]*>/gi) || []) {
    const rel = (attr(tag, 'rel') || '').toLowerCase();
    const type = (attr(tag, 'type') || '').toLowerCase();
    const href = attr(tag, 'href');
    if (rel.split(/\s+/).includes('alternate') && /^application\/(rss|atom|rdf)\+xml$/.test(type) && href && !/\/comments\/feed\/?$/.test(href)) {
      try { out.push({ url: new URL(decode(href), base).href, title: attr(tag, 'title') || '' }); } catch {}
    }
  }
  return out;
}

function tagText(block, names) {
  for (const n of names) {
    const m = block.match(new RegExp(`<${n}(?:\\s[^>]*)?>([\\s\\S]*?)</${n}>`, 'i'));
    if (m) return m[1].replace(/^<!\[CDATA\[|\]\]>$/g, '').trim();
  }
  return null;
}

function parseFeed(xml) {
  const head = xml.slice(0, 2000);
  let kind = null;
  if (/<rss[\s>]/i.test(xml)) kind = 'rss';
  else if (/<feed[\s>]/i.test(head)) kind = 'atom';
  else if (/<rdf:RDF[\s>]/i.test(head)) kind = 'rdf';
  if (!kind) return { parses: false };
  const blocks = kind === 'atom' ? xml.match(/<entry[\s>][\s\S]*?<\/entry>/gi) || [] : xml.match(/<item[\s>][\s\S]*?<\/item>/gi) || [];
  const dates = [];
  const hosts = {};
  let undated = 0;
  for (const b of blocks) {
    const d = tagText(b, ['pubDate', 'published', 'updated', 'dc:date']);
    const ts = d ? Date.parse(d) : NaN;
    if (Number.isFinite(ts)) dates.push(ts); else undated++;
    let link = null;
    if (kind === 'atom') {
      const links = b.match(/<link\b[^>]*>/gi) || [];
      const alt = links.find((l) => !attr(l, 'rel') || attr(l, 'rel') === 'alternate');
      link = alt ? attr(alt, 'href') : null;
    } else {
      link = tagText(b, ['link']) || tagText(b, ['guid']);
    }
    if (link) {
      try { const h = new URL(decode(link)).host.toLowerCase(); hosts[h] = (hosts[h] || 0) + 1; } catch { hosts['(relative/invalid)'] = (hosts['(relative/invalid)'] || 0) + 1; }
    }
  }
  dates.sort((a, b) => a - b);
  return {
    parses: true, kind, items: blocks.length, undated,
    feedTitle: tagText(xml.replace(/<(item|entry)[\s>][\s\S]*$/i, ''), ['title']),
    newest: dates.length ? new Date(dates.at(-1)).toISOString() : null,
    oldest: dates.length ? new Date(dates[0]).toISOString() : null,
    linkHosts: hosts,
  };
}

async function checkFeed(url) {
  const r = await get(url);
  const base = { url, status: r.status, ok: r.ok, error: r.error, ms: r.ms, finalUrl: r.finalUrl !== url ? r.finalUrl : undefined, contentType: r.contentType, etag: r.etag, lastModified: r.lastModified };
  if (!r.ok) return { ...base, parses: false, snippet: r.body ? r.body.slice(0, 160).replace(/\s+/g, ' ') : undefined };
  return { ...base, ...parseFeed(r.body) };
}

async function checkKev(url) {
  const r = await get(url);
  const base = { url, status: r.status, ok: r.ok, error: r.error, ms: r.ms, etag: r.etag, lastModified: r.lastModified };
  if (!r.ok) return { ...base, parses: false };
  try {
    const j = JSON.parse(r.body);
    const added = (j.vulnerabilities || []).map((v) => v.dateAdded).sort();
    return { ...base, parses: true, kind: 'json', items: j.vulnerabilities?.length ?? 0, catalogVersion: j.catalogVersion, newest: added.at(-1) || j.dateReleased };
  } catch (e) {
    return { ...base, parses: false, error: 'invalid JSON' };
  }
}

async function checkSource(src) {
  const out = { id: src.id, type: src.type, discoveryPages: [], feeds: [] };
  if (src.json) {
    for (const u of src.json) out.feeds.push(await checkKev(u));
    return out;
  }
  const urls = new Set(src.feeds || []);
  for (const page of src.discover || []) {
    const r = await get(page);
    const found = r.ok ? discoverFeeds(r.body, r.finalUrl || page) : [];
    out.discoveryPages.push({ url: page, status: r.status, error: r.error, found });
    found.forEach((f) => urls.add(f.url));
  }
  for (const u of src.guess || []) urls.add(u);
  for (const u of urls) out.feeds.push(await checkFeed(u));
  return out;
}

async function pool(items, n, fn) {
  const results = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: n }, async () => {
    while (i < items.length) { const k = i++; results[k] = await fn(items[k]); }
  }));
  return results;
}

const results = await pool(sources, CONCURRENCY, checkSource);
const report = { generatedAt: new Date().toISOString(), userAgent: UA, results };

await mkdir('feedcheck-results', { recursive: true });
await writeFile('feedcheck-results/results.json', JSON.stringify(report, null, 2));

const rows = ['| Source | Feed | HTTP | Parses | Items | Newest | Link hosts |', '|---|---|---|---|---|---|---|'];
for (const s of results) {
  if (!s.feeds.length) {
    const p = s.discoveryPages.map((d) => `${d.status || d.error}`).join(', ');
    rows.push(`| ${s.id} | (no feed found; page ${p}) | | | | | |`);
  }
  for (const f of s.feeds) {
    rows.push(`| ${s.id} | ${f.url} | ${f.status || f.error} | ${f.parses ? f.kind : 'no'} | ${f.items ?? ''} | ${f.newest ?? ''} | ${Object.keys(f.linkHosts || {}).join(' ')} |`);
  }
}
const md = `# Feed check ${report.generatedAt}\n\n${rows.join('\n')}\n`;
await writeFile('feedcheck-results/results.md', md);
if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, md);
console.log(md);
