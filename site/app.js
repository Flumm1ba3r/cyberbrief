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
  watch: store.get('watch', []), // watchlist terms
  hideRead: store.get('hideRead', false),
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

// --- watchlist ---------------------------------------------------------------------

let watchRe = null;
function setWatch(terms) {
  state.watch = terms;
  const esc = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Whole words only, so "Edge" doesn't match "knowledge".
  watchRe = terms.length ? new RegExp(`(?:^|[^\\p{L}\\p{N}])(${terms.map(esc).join('|')})(?=$|[^\\p{L}\\p{N}])`, 'iu') : null;
}
setWatch(state.watch);

/** The watchlist term a story matches, or null. */
function watchHit(s) {
  if (!watchRe) return null;
  const hay = [s.title, s.summary, ...(s.cves || []), ...s.sources.map((x) => x.title), ...(s.kev || []).map((k) => `${k.vendor} ${k.product}`)].join(' \n ');
  const m = hay.match(watchRe);
  return m ? state.watch.find((t) => t.toLowerCase() === m[1].toLowerCase()) || m[1] : null;
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
  el.querySelector('.deep').hidden = !story.deepDive;
  const hit = watchHit(story);
  if (hit) {
    el.classList.add('watched');
    const w = el.querySelector('.watch');
    w.hidden = false;
    w.textContent = `★ ${hit}`;
  }
  const n = new Set(story.sources.map((s) => s.name)).size;
  el.querySelector('.when').textContent = `${ago(story.updated || story.published)}${n > 1 ? ` · ${n} sources` : ''}`;

  el.querySelector('.title').textContent = story.title;
  el.querySelector('.summary').textContent = story.summary;
  const timeline = story.timeline || [];
  if (timeline.length) {
    el.querySelector('.upd').hidden = false;
    const note = el.querySelector('.upd-note');
    note.hidden = false;
    note.textContent = story.followUpNote || `New development in a story from ${dayLabel(timeline[0].date).toLowerCase()}`;
    const btn = el.querySelector('.tl-btn');
    const ol = el.querySelector('.timeline');
    btn.hidden = false;
    btn.textContent = `Timeline (${timeline.length + 1})`;
    btn.setAttribute('aria-expanded', 'false');
    for (const t of [...timeline, { title: story.title, date: story.published, source: story.sources[0].name, url: story.sources[0].url, current: true }]) {
      const li = document.createElement('li');
      if (t.current) li.className = 'current';
      const when = document.createElement('span');
      when.className = 'tl-date';
      when.textContent = `${new Date(t.date).toLocaleDateString(undefined, { day: 'numeric', month: 'short' })} · ${t.source}`;
      const url = safeUrl(t.url);
      const title = document.createElement(url ? 'a' : 'span');
      title.className = 'tl-title';
      title.textContent = t.title;
      if (url) { title.href = url; title.target = '_blank'; title.rel = 'noopener noreferrer'; }
      li.append(when, title);
      if (t.note) {
        const n = document.createElement('span');
        n.className = 'tl-note';
        n.textContent = t.note;
        li.append(n);
      }
      ol.append(li);
    }
    btn.addEventListener('click', () => {
      const open = ol.hidden;
      ol.hidden = !open;
      btn.setAttribute('aria-expanded', String(open));
      btn.textContent = open ? 'Hide' : `Timeline (${timeline.length + 1})`;
    });
  }
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
    const info = story.cveInfo?.[c];
    if (info) {
      const parts = [];
      if (info.cvss != null) {
        const sev = document.createElement('span');
        sev.className = `sev sev-${info.severity || 'none'}`;
        sev.textContent = info.cvss.toFixed(1);
        a.append(' ', sev);
        parts.push(`CVSS ${info.cvss} (${info.severity})`);
      }
      if (info.epss != null) {
        const ep = document.createElement('span');
        ep.className = 'epss';
        ep.textContent = `EPSS ${info.epss < 0.01 ? '<1' : Math.round(info.epss * 100)}%`;
        a.append(' ', ep);
        parts.push(`${(info.epss * 100).toFixed(1)}% chance of exploitation in the next 30 days (EPSS)`);
      }
      if (info.exploitation === 'active') parts.push('CISA: actively exploited');
      a.title = [info.title, ...parts].filter(Boolean).join(' · ');
    }
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

const byDate = (a, b) => Date.parse(b.updated || b.published) - Date.parse(a.updated || a.published);
// Watchlist matches rank higher in Top.
const topScore = (s) => (watchHit(s) ? s.score * 1.6 + 5 : s.score);

function baseSet() {
  const stories = state.data?.stories || [];
  if (state.view === 'saved') return state.saved;
  if (state.view === 'week') {
    const byId = new Map(stories.map((s) => [s.id, s]));
    return (state.data?.week?.storyIds || []).map((id) => byId.get(id)).filter(Boolean);
  }
  // Deep dives stay for 30 days, so they are listed from all stories, newest first.
  if (state.category === 'Deep dives') return stories.filter((s) => s.deepDive).sort(byDate);
  if (state.view === 'latest') return stories.filter((s) => !s.deepDive || Date.now() - Date.parse(s.published) < 7 * 86400000).sort(byDate);
  const cutoff = Date.now() - TOP_HOURS * 3600 * 1000;
  const recent = stories.filter((s) => Date.parse(s.updated || s.published) >= cutoff);
  return (recent.length >= 10 ? recent : stories).slice().sort((a, b) => topScore(b) - topScore(a));
}

function matches(story, words) {
  if (!words.length) return true;
  const hay = [story.title, story.summary, story.whyItMatters, ...(story.cves || []), ...story.sources.map((s) => `${s.name} ${s.title}`)]
    .join(' ')
    .toLowerCase();
  return words.every((w) => hay.includes(w));
}

// Filters across categories: watchlist matches, stories naming a CVE, and deep dives.
const hasCve = (s) => (s.cves || []).length > 0;
const SPECIAL = { Watchlist: (s) => !!watchHit(s), CVE: hasCve, 'Deep dives': (s) => !!s.deepDive };
const inCategory = (s, c) => c === 'All' || (SPECIAL[c] ? SPECIAL[c](s) : s.category === c);

function renderChips(base) {
  const counts = new Map();
  for (const s of base) counts.set(s.category, (counts.get(s.category) || 0) + 1);
  const special = {};
  for (const [name, test] of Object.entries(SPECIAL)) {
    // Deep dives are counted over everything (they reach back 30 days); the rest over the current view.
    const pool = name === 'Deep dives' && state.view !== 'saved' && state.view !== 'week' ? state.data?.stories || [] : base;
    special[name] = pool.filter(test).length;
  }
  const cats = ['All', ...Object.keys(SPECIAL).filter((c) => special[c] || c === state.category), ...Object.keys(CATEGORY_VARS).filter((c) => counts.has(c))];
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
      count.textContent = c === 'All' ? base.length : c in SPECIAL ? special[c] : counts.get(c);
      if (c === 'Watchlist') b.classList.add('chip-watch');
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
  const hideRead = state.hideRead && state.view !== 'saved';
  const matching = base.filter((s) => inCategory(s, state.category) && matches(s, words));
  const shown = hideRead ? matching.filter((s) => !state.read.has(s.id)) : matching;

  const nodes = [];
  if (state.view === 'week' && state.data) nodes.push(recapBox());

  if (!shown.length) {
    const p = document.createElement('p');
    p.className = 'empty';
    p.textContent = !state.data && state.view !== 'saved'
      ? 'Loading…'
      : state.view === 'saved' && !state.saved.length
        ? 'Nothing saved yet. Tap the bookmark on a story to keep it here.'
        : hideRead && matching.length
          ? 'You’re all caught up. Read stories are hidden (change this in settings).'
          : 'No stories match.';
    nodes.push(p);
    list.replaceChildren(...nodes);
    return;
  }

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

const timeOf = (ms) => new Date(ms).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });

/** When the next scheduled build should be live, or null if the last one is overdue. */
function nextUpdate(data) {
  // The workflow runs at minute 17 of every hour (UTC); publishing takes a minute or two.
  const every = data.updateEveryHours || 1;
  const d = new Date();
  d.setUTCMinutes(19, 0, 0);
  while (d.getUTCHours() % every !== 0 || d <= Date.now()) d.setUTCHours(d.getUTCHours() + 1);
  const overdue = Date.now() - Date.parse(data.generatedAt) > (every + 0.5) * 3600 * 1000;
  return overdue ? null : d;
}

function statusText(d) {
  const next = nextUpdate(d);
  return `Updated ${ago(d.generatedAt)} · ${next ? `next ${timeOf(next)}` : 'next update delayed'}`;
}

// The line under "CyberBrief": normally when the briefing was built and the next update is due;
// briefly replaced by the result of tapping refresh.
let flashTimer;
function setStatus(text, flash = false) {
  const el = $('#updated');
  clearTimeout(flashTimer);
  el.textContent = text;
  el.classList.toggle('flash', flash);
  if (flash) flashTimer = setTimeout(() => { el.classList.remove('flash'); if (state.data) el.textContent = statusText(state.data); }, 5000);
}

function recapBox() {
  const week = state.data.week || {};
  const box = document.createElement('section');
  box.className = 'recap';
  const h = document.createElement('h2');
  h.textContent = 'The week in security';
  const p = document.createElement('p');
  p.textContent = week.recap || 'The 10 most important stories of the past 7 days, ranked by importance rather than freshness.';
  box.append(h, p);
  if (week.recap) {
    const small = document.createElement('small');
    small.className = 'muted';
    small.textContent = `Written by Claude from the stories below, ${ago(week.recapAt)}.`;
    box.append(small);
  }
  return box;
}

function renderStatus() {
  const d = state.data;
  if (!d) return;
  if (!$('#updated').classList.contains('flash')) setStatus(statusText(d));
  const ok = d.sources.filter((s) => s.ok);
  const bad = d.sources.filter((s) => !s.ok);
  const foot = $('#foot');
  const p = document.createElement('p');
  p.textContent = `${d.summarizer === 'claude' ? 'Summaries and ranking by Claude, from' : 'Summaries are the outlets’ own excerpts, from'} ${ok.length} of ${d.sources.length} sources. Briefing built ${new Date(d.generatedAt).toLocaleString()}; updates every ${d.updateEveryHours === 1 || !d.updateEveryHours ? 'hour' : `${d.updateEveryHours} hours`}. `;
  if (d.repo && /^[\w.-]+\/[\w.-]+$/.test(d.repo)) {
    const a = document.createElement('a');
    a.href = `https://github.com/${d.repo}/actions/workflows/briefing.yml`;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = 'Update now on GitHub ↗';
    p.append(a);
  }
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

async function load(manual = false) {
  const btn = $('#refresh');
  btn.classList.add('spinning');
  if (manual) setStatus('Checking for updates…', true);
  const before = state.data;
  try {
    const res = await fetch(DATA_URL, { cache: 'no-cache' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    state.data = data;
    state.fetchedAt = Date.now();
    const offline = res.headers.get('x-cyberbrief-cache') === 'offline';
    banner(offline ? `You’re offline. Showing the briefing from ${ago(data.generatedAt)}.` : null);
    if (manual && offline) {
      setStatus('Offline · showing saved briefing', true);
    } else if (manual && before && before.generatedAt !== data.generatedAt) {
      const oldIds = new Set(before.stories.map((s) => s.id));
      const added = data.stories.filter((s) => !oldIds.has(s.id)).length;
      setStatus(added ? `✓ ${added} new ${added === 1 ? 'story' : 'stories'}` : '✓ Updated · no new stories', true);
    } else if (manual) {
      const next = nextUpdate(data);
      setStatus(`✓ Up to date · ${next ? `next update ${timeOf(next)}` : 'next update delayed'}`, true);
    }
    renderStatus();
    render();
  } catch (e) {
    if (!state.data) {
      banner('Couldn’t load the briefing. Check your connection and tap refresh.');
      list.replaceChildren();
    }
    if (manual || !state.data) setStatus('Couldn’t refresh · check your connection', true);
  } finally {
    btn.classList.remove('spinning');
  }
}

// Keep "Updated … ago" current while the app stays open.
setInterval(() => { if (state.data && !$('#updated').classList.contains('flash')) setStatus(statusText(state.data)); }, 60 * 1000);

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

$('#refresh').addEventListener('click', () => load(true));

const dlg = $('#settings-dlg');
$('#settings').addEventListener('click', () => {
  $('#watch').value = state.watch.join(', ');
  $('#hide-read').checked = state.hideRead;
  dlg.showModal();
});
dlg.addEventListener('close', () => {
  const terms = [...new Set($('#watch').value.split(/[,\n]/).map((t) => t.trim()).filter((t) => t.length >= 2))].slice(0, 40);
  store.set('watch', terms);
  setWatch(terms);
  render();
});
$('#hide-read').addEventListener('change', (e) => {
  state.hideRead = e.target.checked;
  store.set('hideRead', state.hideRead);
  render();
});
$('#mark-all').addEventListener('click', () => {
  const ids = (state.data?.stories || []).map((s) => s.id).filter((id) => !state.read.has(id));
  ids.forEach((id) => state.read.add(id));
  store.set('read', [...state.read].slice(-3000));
  dlg.close();
  setStatus(ids.length ? `✓ Marked ${ids.length} ${ids.length === 1 ? 'story' : 'stories'} as read` : 'Nothing unread', true);
});

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && Date.now() - state.fetchedAt > 10 * 60 * 1000) load();
});

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').catch(() => {});
}

render();
load();
