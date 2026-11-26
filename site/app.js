// CyberBrief front end. Reads data/briefing.json (built by scripts/build-briefing.mjs) and renders it.
// All story text comes from third-party feeds, so it is only ever inserted with textContent.

const DATA_URL = 'data/briefing.json';
const TOP_HOURS = 72;
const PAGE = 25;
const CATEGORY_VARS = {
  'Exploited vulnerability': '--c-exploited',
  Vulnerability: '--c-vuln',
  Ransomware: '--c-ransom',
  Breach: '--c-breach',
  'Threat actor': '--c-actor',
  Malware: '--c-malware',
  'Law & policy': '--c-law',
  Privacy: '--c-privacy',
  Advisory: '--c-advisory',
  Industry: '--c-industry',
};
const SHORT = { 'Exploited vulnerability': 'Exploited' };

// --- storage (per device; the app works without it) -------------------------

const store = {
  get(key, fallback) {
    try { const v = localStorage.getItem(`cb.${key}`); return v === null ? fallback : JSON.parse(v); } catch { return fallback; }
  },
  set(key, value) {
    try { localStorage.setItem(`cb.${key}`, JSON.stringify(value)); } catch { /* storage unavailable */ }
  },
};

const state = {
  data: null,
  view: store.get('view', 'top'),
  category: 'All',
  query: '',
  limit: PAGE,
  saved: store.get('saved', []), // full story objects, so they outlive the 7-day window
  read: new Set(store.get('read', [])),
  since: store.get('lastVisit', null),
  fetchedAt: 0,
};
store.set('lastVisit', Date.now());

const $ = (sel) => document.querySelector(sel);
const list = $('#list');
const tpl = $('#card-tpl');

// --- helpers ------------------------------------------------------------------

function safeUrl(u) {
  try { const url = new URL(u); return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null; } catch { return null; }
}

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto', style: 'short' });
function ago(iso) {
  const diff = (Date.parse(iso) - Date.now()) / 1000;
  const abs = Math.abs(diff);
  if (abs < 60) return 'just now';
  if (abs < 3600) return rtf.format(Math.round(diff / 60), 'minute');
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), 'hour');
  return rtf.format(Math.round(diff / 86400), 'day');
}

function dayLabel(iso) {
  const d = new Date(iso);
  const today = new Date();
  const startOf = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const days = Math.round((startOf(today) - startOf(d)) / 86400000);
  if (days === 0) return 'Today';
  if (days === 1) return 'Yesterday';
  return d.toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'short' });
}

const isNew = (s) => state.since && s.sources.some((src) => Date.parse(src.firstSeen || src.published) > state.since);
const isSaved = (id) => state.saved.some((s) => s.id === id);

function markRead(id) {
  if (state.read.has(id)) return;
  state.read.add(id);
  store.set('read', [...state.read].slice(-1500));
  document.querySelectorAll(`.card[data-id="${CSS.escape(id)}"]`).forEach((el) => el.classList.add('read'));
}

function toggleSave(story, btn) {
  if (isSaved(story.id)) {
    state.saved = state.saved.filter((s) => s.id !== story.id);
  } else {
    state.saved.unshift({ ...story, savedAt: Date.now() });
  }
  store.set('saved', state.saved.slice(0, 300));
  btn.setAttribute('aria-pressed', String(isSaved(story.id)));
  btn.setAttribute('aria-label', isSaved(story.id) ? 'Remove from saved' : 'Save');
  if (state.view === 'saved') render();
}

// --- rendering ------------------------------------------------------------------

function card(story) {
  const el = tpl.content.firstElementChild.cloneNode(true);
  el.dataset.id = story.id;
  if (state.read.has(story.id)) el.classList.add('read');

  const cat = el.querySelector('.cat');
  cat.textContent = SHORT[story.category] || story.category;
  el.style.setProperty('--cat', `var(${CATEGORY_VARS[story.category] || '--c-industry'})`);
  el.querySelector('.kev').hidden = !(story.kev || story.inKev);
  el.querySelector('.new').hidden = !isNew(story);
  const n = new Set(story.sources.map((s) => s.name)).size;
  el.querySelector('.when').textContent = `${ago(story.updated || story.published)}${n > 1 ? ` · ${n} sources` : ''}`;

  el.querySelector('.title').textContent = story.title;
  el.querySelector('.summary').textContent = story.summary;
  if (story.whyItMatters) {
    const why = el.querySelector('.why');
    why.hidden = false;
    why.querySelector('span').textContent = story.whyItMatters;
  }

  const cves = el.querySelector('.cves');
  for (const c of (story.cves || []).slice(0, 6)) {
    const a = document.createElement('a');
    a.href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c)}`;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = c;
    cves.append(a);
  }

  const [lead, ...rest] = story.sources;
  const read = el.querySelector('.read');
  const leadUrl = safeUrl(lead.url);
  if (leadUrl) {
    read.href = leadUrl;
    read.textContent = `Read on ${lead.name} ↗`;
    read.addEventListener('click', () => markRead(story.id));
  } else {
    read.remove();
  }

  if (rest.length) {
    const more = el.querySelector('.more');
    const others = el.querySelector('.others');
    more.hidden = false;
    more.textContent = `+${rest.length} more`;
    more.setAttribute('aria-expanded', 'false');
    for (const s of rest) {
      const url = safeUrl(s.url);
      if (!url) continue;
      const li = document.createElement('li');
      const a = document.createElement('a');
      a.href = url;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      const src = document.createElement('span');
      src.className = 'src';
      src.textContent = s.name;
      a.append(src, document.createTextNode(s.title));
      a.addEventListener('click', () => markRead(story.id));
      li.append(a);
      others.append(li);
    }
    more.addEventListener('click', () => {
      const open = others.hidden;
      others.hidden = !open;
      more.setAttribute('aria-expanded', String(open));
      more.textContent = open ? 'Fewer' : `+${rest.length} more`;
    });
  }

  const save = el.querySelector('.save');
  save.setAttribute('aria-pressed', String(isSaved(story.id)));
  save.setAttribute('aria-label', isSaved(story.id) ? 'Remove from saved' : 'Save');
  save.addEventListener('click', () => toggleSave(story, save));

  if (navigator.share && leadUrl) {
    const share = el.querySelector('.share');
    share.hidden = false;
    share.addEventListener('click', () => navigator.share({ title: story.title, url: leadUrl }).catch(() => {}));
  }
  return el;
}

function baseSet() {
  const stories = state.data?.stories || [];
  if (state.view === 'saved') return state.saved;
  if (state.view === 'latest') {
    return [...stories].sort((a, b) => Date.parse(b.updated || b.published) - Date.parse(a.updated || a.published));
  }
  const cutoff = Date.now() - TOP_HOURS * 3600 * 1000;
  const recent = stories.filter((s) => Date.parse(s.updated || s.published) >= cutoff);
  return (recent.length >= 10 ? recent : stories).slice().sort((a, b) => b.score - a.score);
}

function matches(story, words) {
  if (!words.length) return true;
  const hay = [story.title, story.summary, story.whyItMatters, ...(story.cves || []), ...story.sources.map((s) => `${s.name} ${s.title}`)]
    .join(' ')
    .toLowerCase();
  return words.every((w) => hay.includes(w));
}

function renderChips(base) {
  const counts = new Map();
  for (const s of base) counts.set(s.category, (counts.get(s.category) || 0) + 1);
  const cats = ['All', ...Object.keys(CATEGORY_VARS).filter((c) => counts.has(c))];
  if (!cats.includes(state.category)) state.category = 'All';
  const chips = $('#chips');
  chips.replaceChildren(
    ...cats.map((c) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.setAttribute('aria-pressed', String(c === state.category));
      b.textContent = SHORT[c] || c;
      const count = document.createElement('span');
      count.className = 'count';
      count.textContent = c === 'All' ? base.length : counts.get(c);
      b.append(count);
      b.addEventListener('click', () => { state.category = c; state.limit = PAGE; render(); });
      return b;
    }),
  );
}

function render() {
  document.querySelectorAll('.tabs button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.view === state.view)));
  const base = baseSet();
  renderChips(base);
  const words = state.query.toLowerCase().split(/\s+/).filter(Boolean);
  const shown = base.filter((s) => (state.category === 'All' || s.category === state.category) && matches(s, words));

  if (!shown.length) {
    const p = document.createElement('p');
    p.className = 'empty';
    p.textContent = !state.data && state.view !== 'saved'
      ? 'Loading…'
      : state.view === 'saved' && !state.saved.length
        ? 'Nothing saved yet. Tap the bookmark on a story to keep it here.'
        : 'No stories match.';
    list.replaceChildren(p);
    return;
  }

  const nodes = [];
  let lastDay = null;
  for (const s of shown.slice(0, state.limit)) {
    if (state.view === 'latest') {
      const d = dayLabel(s.updated || s.published);
      if (d !== lastDay) {
        const h = document.createElement('h3');
        h.className = 'day';
        h.textContent = d;
        nodes.push(h);
        lastDay = d;
      }
    }
    nodes.push(card(s));
  }
  if (shown.length > state.limit) {
    const b = document.createElement('button');
    b.className = 'show-more';
    b.type = 'button';
    b.textContent = `Show ${Math.min(PAGE, shown.length - state.limit)} more`;
    b.addEventListener('click', () => { state.limit += PAGE; render(); });
    nodes.push(b);
  }
  list.replaceChildren(...nodes);
}

function renderStatus() {
  const d = state.data;
  if (!d) return;
  $('#updated').textContent = `Updated ${ago(d.generatedAt)}`;
  const ok = d.sources.filter((s) => s.ok);
  const bad = d.sources.filter((s) => !s.ok);
  const foot = $('#foot');
  const p = document.createElement('p');
  p.textContent = `${d.summarizer === 'claude' ? 'Summaries and ranking by Claude, from' : 'Summaries are the outlets’ own excerpts, from'} ${ok.length} of ${d.sources.length} sources. Briefing built ${new Date(d.generatedAt).toLocaleString()}.`;
  const det = document.createElement('details');
  const sum = document.createElement('summary');
  sum.textContent = bad.length ? `${bad.length} source${bad.length > 1 ? 's' : ''} failed this run` : 'All sources';
  if (bad.length) sum.className = 'bad';
  const ul = document.createElement('ul');
  for (const s of [...bad, ...ok]) {
    const li = document.createElement('li');
    li.textContent = s.ok ? `${s.name}: ${s.items} items` : `${s.name}: failed (${s.error})`;
    if (!s.ok) li.className = 'bad';
    ul.append(li);
  }
  det.append(sum, ul);
  foot.replaceChildren(p, det);
}

function banner(text) {
  const b = $('#banner');
  if (!text) { b.hidden = true; return; }
  const div = document.createElement('div');
  div.textContent = text;
  b.replaceChildren(div);
  b.hidden = false;
}

// --- data -------------------------------------------------------------------------

async function load() {
  const btn = $('#refresh');
  btn.classList.add('spinning');
  try {
    const res = await fetch(DATA_URL, { cache: 'no-cache' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    state.data = data;
    state.fetchedAt = Date.now();
    const stale = res.headers.get('x-cyberbrief-cache') === 'offline';
    banner(stale ? `You’re offline. Showing the briefing from ${ago(data.generatedAt)}.` : null);
    renderStatus();
    render();
  } catch (e) {
    if (!state.data) {
      banner('Couldn’t load the briefing. Check your connection and tap refresh.');
      list.replaceChildren();
    } else {
      banner('Couldn’t refresh. Showing the last briefing.');
    }
  } finally {
    btn.classList.remove('spinning');
  }
}

// --- events -------------------------------------------------------------------------

document.querySelectorAll('.tabs button').forEach((b) =>
  b.addEventListener('click', () => {
    state.view = b.dataset.view;
    state.limit = PAGE;
    state.category = 'All';
    store.set('view', state.view);
    render();
    window.scrollTo({ top: 0 });
  }),
);

let qTimer;
$('#q').addEventListener('input', (e) => {
  clearTimeout(qTimer);
  qTimer = setTimeout(() => { state.query = e.target.value; state.limit = PAGE; render(); }, 120);
});

$('#refresh').addEventListener('click', load);

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && Date.now() - state.fetchedAt > 10 * 60 * 1000) load();
});

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').catch(() => {});
}

render();
load();
