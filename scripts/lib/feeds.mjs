// Fetching and parsing RSS, Atom and RDF feeds, plus CISA's KEV catalog. Dependency-free.
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

export const USER_AGENT = 'CyberBrief/1.0 (personal security-news reader)';
const TIMEOUT_MS = 20000;
const MAX_BYTES = 8 * 1024 * 1024;

// --- text helpers -----------------------------------------------------------

const NAMED = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', hellip: '…', mdash: '—', ndash: '–',
  rsquo: '’', lsquo: '‘', rdquo: '”', ldquo: '“', laquo: '«', raquo: '»', copy: '©', reg: '®',
  trade: '™', bull: '•', middot: '·', eacute: 'é', egrave: 'è', uuml: 'ü', ouml: 'ö', auml: 'ä', szlig: 'ß',
};

export function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === '#') {
      const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(cp) && cp > 0 && cp < 0x110000 ? String.fromCodePoint(cp) : m;
    }
    return NAMED[e.toLowerCase()] ?? m;
  });
}

const unCdata = (s) => s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');

/** Turn a feed field (possibly escaped HTML) into clean plain text. */
export function toPlainText(raw) {
  if (!raw) return '';
  let s = unCdata(raw);
  // Escaped HTML (&lt;p&gt;) becomes real HTML first, so the tags can be stripped.
  if (/&lt;\/?[a-z]/i.test(s)) s = decodeEntities(s);
  s = s
    .replace(/<(script|style|figure|figcaption|iframe|noscript)\b[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<br\s*\/?>|<\/(p|div|li|h\d)>/gi, '\n')
    .replace(/<[^>]+>/g, ' ');
  s = decodeEntities(s);
  return s.replace(/[ \t ]+/g, ' ').replace(/\s*\n\s*/g, '\n').replace(/\n{2,}/g, '\n').trim();
}

/** Drop the boilerplate many feeds append ("The post X appeared first on Y", "Continue reading"). */
export function cleanExcerpt(text) {
  return text
    .replace(/\bThe post .{0,300}? appeared first on .{0,120}?\.?$/s, '')
    .replace(/\b(Continue reading|Read more|Read the full (story|article)|Keep reading)\b.*$/is, '')
    .replace(/\[(…|\.\.\.)\]\s*$/, '…')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Cut text to about `max` characters, preferring a sentence boundary. */
export function truncate(text, max) {
  if (text.length <= max) return text;
  const cut = text.slice(0, max);
  const lastStop = Math.max(cut.lastIndexOf('. '), cut.lastIndexOf('! '), cut.lastIndexOf('? '));
  if (lastStop > max * 0.5) return cut.slice(0, lastStop + 1);
  return cut.replace(/\s+\S*$/, '') + '…';
}

export function safeHttpUrl(u, base) {
  try {
    const url = new URL(decodeEntities(u.trim()), base);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null;
  } catch {
    return null;
  }
}

// --- XML helpers --------------------------------------------------------------

function attr(tag, name) {
  const m = tag.match(new RegExp(`\\s${name}\\s*=\\s*("([^"]*)"|'([^']*)')`, 'i'));
  return m ? (m[2] ?? m[3]) : null;
}

function field(block, names) {
  for (const n of names) {
    const re = new RegExp(`<${n}(?:\\s[^>]*)?>([\\s\\S]*?)</${n}>`, 'i');
    const m = block.match(re);
    if (m && m[1].trim()) return m[1].trim();
  }
  return null;
}

function parseDate(s) {
  if (!s) return null;
  const t = Date.parse(unCdata(s).trim());
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

/** Parse RSS 2.0, RSS 1.0 (RDF) or Atom into a flat list of items. */
export function parseFeed(xml, baseUrl) {
  const head = xml.slice(0, 4000);
  const isAtom = /<feed[\s>]/i.test(head) && !/<rss[\s>]/i.test(head);
  const blocks = isAtom
    ? xml.match(/<entry[\s>][\s\S]*?<\/entry>/gi) || []
    : xml.match(/<item[\s>][\s\S]*?<\/item>/gi) || [];
  if (!blocks.length && !/<(rss|feed|rdf:RDF)[\s>]/i.test(head)) throw new Error('not a feed');

  const items = [];
  for (const b of blocks) {
    const title = toPlainText(field(b, ['title']) || '');
    let link = null;
    if (isAtom) {
      const links = b.match(/<link\b[^>]*>/gi) || [];
      const alt = links.find((l) => !attr(l, 'rel') || attr(l, 'rel') === 'alternate') || links[0];
      link = alt ? attr(alt, 'href') : null;
    } else {
      link = field(b, ['link']);
      if (!link) {
        const guid = b.match(/<guid(\s[^>]*)?>([\s\S]*?)<\/guid>/i);
        if (guid && !/isPermaLink\s*=\s*["']false/i.test(guid[1] || '')) link = guid[2];
      }
    }
    link = link ? safeHttpUrl(unCdata(link), baseUrl) : null;
    if (!title || !link) continue;

    const body = field(b, ['description', 'summary', 'content:encoded', 'content']) || '';
    const categories = [...b.matchAll(/<category(?:\s[^>]*)?>([\s\S]*?)<\/category>/gi)].map((m) => toPlainText(m[1]))
      .concat([...b.matchAll(/<category\b[^>]*\sterm\s*=\s*"([^"]*)"/gi)].map((m) => decodeEntities(m[1])))
      .filter(Boolean);

    items.push({
      title,
      url: link,
      published: parseDate(field(b, ['pubDate', 'published', 'dc:date', 'updated', 'a10:updated'])),
      excerpt: cleanExcerpt(toPlainText(body)),
      categories,
    });
  }
  return items;
}

// --- fetching ---------------------------------------------------------------

async function fetchText(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.9, application/json;q=0.9, */*;q=0.5',
      },
      redirect: 'follow',
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    if (text.length > MAX_BYTES) throw new Error('response too large');
    return { text, finalUrl: res.url || url };
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('timeout');
    throw new Error(e.cause?.code || e.message);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Load one source. With CYBERBRIEF_FIXTURES set, reads <dir>/<id>.xml (or .json) instead of the network,
 * so the pipeline can be tested offline.
 */
export async function loadSource(src) {
  const fixtures = process.env.CYBERBRIEF_FIXTURES;
  let text, finalUrl;
  if (fixtures) {
    const file = join(fixtures, `${src.id}.${src.kind === 'kev' ? 'json' : 'xml'}`);
    text = await readFile(file, 'utf8');
    finalUrl = src.url;
  } else {
    try {
      ({ text, finalUrl } = await fetchText(src.url));
    } catch (e) {
      if (!src.fallbackUrl) throw e;
      ({ text, finalUrl } = await fetchText(src.fallbackUrl));
    }
  }
  return src.kind === 'kev' ? parseKev(text) : parseFeed(text, finalUrl);
}

// --- CISA Known Exploited Vulnerabilities -------------------------------------

/** Returns KEV entries; the build groups them into one story per day they were added. */
function parseKev(text) {
  const j = JSON.parse(text);
  return (j.vulnerabilities || []).map((v) => ({
    kev: true,
    cve: v.cveID,
    vendor: v.vendorProject,
    product: v.product,
    name: v.vulnerabilityName,
    description: v.shortDescription,
    dateAdded: v.dateAdded,
    dueDate: v.dueDate,
    ransomware: v.knownRansomwareCampaignUse === 'Known',
  }));
}
