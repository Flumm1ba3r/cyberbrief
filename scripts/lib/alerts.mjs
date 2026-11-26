// Push alerts for critical stories via ntfy (https://ntfy.sh). Runs only when the NTFY_TOPIC secret is set.
//
// A story triggers an alert when it is:
//  - critical: rated 5/5 by Claude (without Claude: a very high heuristic score), or
//  - on the alert watchlist (ALERT_WATCHLIST variable) AND exploited or important (KEV, actively exploited CVE, rated 4+), or
//  - a follow-up to an important story (a development in a thread rated 4+).
// Each story alerts once. At most MAX_PER_RUN alerts are sent per run; the rest are rolled into one summary alert.
import { createHash } from 'node:crypto';
import { USER_AGENT } from './feeds.mjs';

const SERVER = process.env.NTFY_SERVER || 'https://ntfy.sh';
const MAX_PER_RUN = 4;
const FRESH_HOURS = 12; // only alert stories CyberBrief first saw recently, never a backlog

/** Link that opens a story inside the app (see the #/story/ route in site/app.js). */
export const storyLink = (appUrl, id) => (appUrl ? `${appUrl}#/story/${encodeURIComponent(id)}` : null);

const topicHash = (t) => createHash('sha256').update(t).digest('hex').slice(0, 16);

function watchTerms() {
  return (process.env.ALERT_WATCHLIST || '').split(/[,\n]/).map((t) => t.trim()).filter((t) => t.length >= 2);
}

function watchMatch(story, terms) {
  if (!terms.length) return null;
  const esc = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`(?:^|[^\\p{L}\\p{N}])(${terms.map(esc).join('|')})(?=$|[^\\p{L}\\p{N}])`, 'iu');
  const hay = [story.title, story.summary, ...(story.cves || []), ...(story.kev || []).map((k) => `${k.vendor} ${k.product}`)].join(' \n ');
  const m = hay.match(re);
  return m ? terms.find((t) => t.toLowerCase() === m[1].toLowerCase()) || m[1] : null;
}

/** Why a story deserves an alert, or null. `st` is the internal story (has base, importance, timeline). */
export function alertReason(st, out, { terms, archive, cveCache }) {
  if (st.importance === 5 || (!st.importance && st.base >= 48)) return { priority: 5, label: 'Critical' };
  const exploited = !!st.kev || st.inKev || st.category === 'Exploited vulnerability' || st.cves.some((c) => cveCache[c]?.exploitation === 'active' || (cveCache[c]?.epss ?? 0) >= 0.5);
  const hit = watchMatch(out, terms);
  if (hit && (exploited || (st.importance || 0) >= 4)) return { priority: 4, label: `★ ${hit}` };
  if (st.timeline?.length) {
    const important = (st.importance || 0) >= 4 || st.timeline.some((t) => (archive[t.id]?.importance || 0) >= 4);
    if (important) return { priority: 4, label: 'Update' };
  }
  return null;
}

async function send(topic, msg, log) {
  const res = await fetch(SERVER, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'User-Agent': USER_AGENT },
    body: JSON.stringify({ topic, ...msg }),
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
  log(`  ✉ ${msg.title}`);
}

// --- quiet hours -------------------------------------------------------------------------

/** Parse QUIET_HOURS, e.g. "23:00-07:00 Asia/Singapore". Returns minutes after midnight, or null if unset/invalid. */
export function parseQuiet(raw) {
  const m = (raw || '').trim().match(/^(\d{1,2})(?::(\d{2}))?\s*-\s*(\d{1,2})(?::(\d{2}))?\s*([A-Za-z_]+\/[A-Za-z_\/+-]+|UTC)?$/);
  if (!m || +m[1] > 23 || +m[3] > 23) return null;
  return { start: +m[1] * 60 + +(m[2] || 0), end: +m[3] * 60 + +(m[4] || 0), tz: m[5] || 'UTC' };
}

/** True while notifications should be held back. Quiet hours may span midnight (23:00-07:00). */
export function isQuiet(cfg, at = new Date()) {
  if (!cfg || cfg.start === cfg.end) return false;
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-GB', { timeZone: cfg.tz, hour: '2-digit', minute: '2-digit', hourCycle: 'h23' })
    .formatToParts(at).map((p) => [p.type, p.value]));
  const m = +parts.hour * 60 + +parts.minute;
  return cfg.start < cfg.end ? m >= cfg.start && m < cfg.end : m >= cfg.start || m < cfg.end;
}

function quietNow(log) {
  if (!process.env.QUIET_HOURS) return false;
  const cfg = parseQuiet(process.env.QUIET_HOURS);
  if (!cfg) { log('  QUIET_HOURS setting not understood: use e.g. "23:00-07:00 Asia/Singapore"'); return false; }
  try { return isQuiet(cfg); } catch { log(`  QUIET_HOURS time zone not recognised: ${cfg.tz}`); return false; }
}

/**
 * Send alerts for the given candidates and record them in `alerted` (story id -> ISO time).
 * Never throws: alerts must not break the briefing.
 */
export async function sendAlerts({ candidates, alerted, alertState, appUrl, log }) {
  const topic = process.env.NTFY_TOPIC?.trim();
  if (!topic) return alertState;
  // During quiet hours nothing is sent or marked as sent: the first run afterwards picks up what is still fresh.
  if (quietNow(log)) { log('  Quiet hours: holding alerts'); return alertState; }
  const now = Date.now();
  const hash = topicHash(topic);
  try {
    // Confirm the setup once per topic, so it's obvious alerts are working.
    if (alertState?.topicHash !== hash) {
      await send(topic, {
        title: 'CyberBrief alerts are on',
        message: 'You will get a notification here for critical security stories. Tap to open CyberBrief.',
        tags: ['white_check_mark'],
        priority: 3,
        ...(appUrl ? { click: appUrl } : {}),
      }, log);
      // Don't flood a fresh setup with everything already in the briefing: start counting from now.
      if (!alertState) for (const c of candidates) alerted[c.out.id] = new Date(now).toISOString();
      alertState = { topicHash: hash, since: new Date(now).toISOString() };
      return alertState;
    }

    const fresh = candidates.filter((c) => !alerted[c.out.id] &&
      now - Date.parse(c.out.sources[0]?.firstSeen || c.out.published) < FRESH_HOURS * 3600 * 1000);
    fresh.sort((a, b) => b.reason.priority - a.reason.priority || b.out.score - a.out.score);

    for (const { out, reason } of fresh.slice(0, MAX_PER_RUN)) {
      const lead = out.sources[0];
      const note = out.followUpNote ? `Update: ${out.followUpNote}\n` : '';
      await send(topic, {
        title: `${reason.label}: ${out.title}`.slice(0, 250),
        message: `${note}${out.summary}`.slice(0, 1000),
        priority: reason.priority,
        tags: [reason.priority === 5 ? 'rotating_light' : 'warning'],
        // Tapping opens the story in CyberBrief (summary, all sources, timeline); a button goes straight to the article.
        click: storyLink(appUrl, out.id) || lead.url,
        actions: [
          { action: 'view', label: `Read on ${lead.name}`.slice(0, 40), url: lead.url },
        ],
      }, log);
      alerted[out.id] = new Date(now).toISOString();
    }
    const rest = fresh.slice(MAX_PER_RUN);
    if (rest.length) {
      await send(topic, {
        title: `${rest.length} more important ${rest.length === 1 ? 'story' : 'stories'}`,
        message: rest.map((c) => `• ${c.out.title}`).join('\n').slice(0, 1000),
        priority: 3,
        tags: ['newspaper'],
        ...(appUrl ? { click: appUrl } : {}),
      }, log);
      for (const c of rest) alerted[c.out.id] = new Date(now).toISOString();
    }
    if (!fresh.length) log('  No new alerts');
  } catch (e) {
    log(`  Alert failed: ${e.message}`);
  }
  return alertState;
}

export { watchTerms };

// --- health -----------------------------------------------------------------------------

const DAY = 24 * 3600 * 1000;

/**
 * Track failing sources and Claude errors across runs in `health` (kept in state.json), and alert once a source
 * has failed for a day, or when Claude stops working (repeated at most daily). Returns what the app should show.
 */
export async function checkHealth({ health, status, claudeStats, appUrl, log }) {
  const now = Date.now();
  const iso = new Date(now).toISOString();
  health.sources ||= {};
  for (const s of status) {
    if (s.ok) { delete health.sources[s.id]; continue; }
    health.sources[s.id] ||= { name: s.name, since: iso };
    health.sources[s.id].error = s.error;
  }
  let recovered = false;
  if (claudeStats && claudeStats.attempted > 0) {
    if (claudeStats.succeeded === 0) {
      health.claude ||= { since: iso };
      health.claude.error = claudeStats.lastError;
    } else if (health.claude) {
      recovered = !!health.claude.alertedAt;
      if (recovered) health.recoveredPending = true;
      delete health.claude;
    }
  }

  const topic = process.env.NTFY_TOPIC?.trim();
  const quiet = topic && quietNow(log);
  if (quiet) log('  Quiet hours: holding health alerts');
  if (topic && !quiet) {
    try {
      const longFailing = Object.values(health.sources).filter((s) => now - Date.parse(s.since) >= DAY && !s.alerted);
      if (longFailing.length) {
        await send(topic, {
          title: `CyberBrief: ${longFailing.length} ${longFailing.length === 1 ? 'source has' : 'sources have'} been failing for a day`,
          message: `${longFailing.map((s) => `• ${s.name}: ${s.error}`).join('\n')}\n\nThe briefing still works without them. If this persists, the feed address may have changed.`.slice(0, 1000),
          priority: 3,
          tags: ['wrench'],
          ...(appUrl ? { click: appUrl } : {}),
        }, log);
        for (const s of longFailing) s.alerted = iso;
      }
      if (health.claude && (!health.claude.alertedAt || now - Date.parse(health.claude.alertedAt) >= DAY)) {
        await send(topic, {
          title: 'CyberBrief: Claude summaries stopped working',
          message: `Error: ${health.claude.error}\n\nThe app falls back to the outlets' own excerpts. Common causes: no API credit left, or the key was revoked. Check the Claude Console.`.slice(0, 1000),
          priority: 4,
          tags: ['warning'],
          click: 'https://console.anthropic.com',
        }, log);
        health.claude.alertedAt = iso;
      }
      if (health.recoveredPending && !health.claude) {
        delete health.recoveredPending;
        await send(topic, { title: 'CyberBrief: Claude summaries are working again', message: 'No action needed.', priority: 2, tags: ['white_check_mark'] }, log);
      }
    } catch (e) {
      log(`  Health alert failed: ${e.message}`);
    }
  }
  return {
    claudeError: health.claude ? { error: health.claude.error, since: health.claude.since } : null,
    failingSources: Object.values(health.sources).filter((s) => now - Date.parse(s.since) >= 6 * 3600 * 1000).map((s) => ({ name: s.name, since: s.since, error: s.error })),
  };
}

// --- daily digest -------------------------------------------------------------------------

/** Parse the DIGEST setting, e.g. "08:00 Asia/Singapore" or "7" (7:00 UTC). Returns minutes after midnight. */
function parseDigest(raw) {
  const m = (raw || '').trim().match(/^(\d{1,2})(?::(\d{2}))?\s*([A-Za-z_]+\/[A-Za-z_\/+-]+|UTC)?$/);
  if (!m || +m[1] > 23 || +(m[2] || 0) > 59) return null;
  return { minutes: +m[1] * 60 + +(m[2] || 0), tz: m[3] || 'UTC' };
}

function localParts(tz, at = new Date()) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-CA', {
    timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
  }).formatToParts(at).map((p) => [p.type, p.value]));
  return { date: `${parts.year}-${parts.month}-${parts.day}`, minutes: +parts.hour * 60 + +parts.minute };
}

// The build runs at about :47 each hour, and GitHub sometimes starts scheduled runs late or skips one.
// So the digest goes out with the first run from 20 minutes before the set time to 100 minutes after it.
const DIGEST_EARLY = 20;
const DIGEST_LATE = 100;

/** The local date of the digest that is due now, or null if none is due. Handles times near midnight. */
export function digestDue(cfg, at = new Date()) {
  const local = localParts(cfg.tz, at);
  let diff = local.minutes - cfg.minutes;
  let dayShift = 0;
  if (diff > 720) { diff -= 1440; dayShift = 1; } // e.g. 23:50 for a 00:10 digest: tomorrow's
  if (diff < -720) { diff += 1440; dayShift = -1; } // e.g. 00:30 for a 23:50 digest: yesterday's
  if (diff < -DIGEST_EARLY || diff >= DIGEST_LATE) return null;
  if (!dayShift) return local.date;
  const d = new Date(`${local.date}T12:00:00Z`);
  d.setUTCDate(d.getUTCDate() + dayShift);
  return d.toISOString().slice(0, 10);
}

/** Once a day around the configured local time, send the top 5 stories. Returns the updated digest state. */
export async function sendDigest({ stories, digestState, appUrl, log }) {
  const topic = process.env.NTFY_TOPIC?.trim();
  const cfg = parseDigest(process.env.DIGEST);
  if (!topic || !process.env.DIGEST) return digestState;
  if (!cfg) { log(`  DIGEST setting not understood: use e.g. "08:00 Asia/Singapore"`); return digestState; }
  let due;
  try { due = digestDue(cfg); } catch { log(`  DIGEST time zone not recognised: ${cfg.tz}`); return digestState; }
  if (!due || digestState?.date === due) return digestState;
  const recent = stories.filter((s) => Date.now() - Date.parse(s.published) < 24 * 3600 * 1000);
  const top = (recent.length >= 3 ? recent : stories).slice(0, 5);
  if (!top.length) return digestState;
  try {
    await send(topic, {
      title: 'Your daily CyberBrief: top 5',
      message: top.map((s, i) => `${i + 1}. ${s.title}`).join('\n').slice(0, 1000),
      priority: 3,
      tags: ['newspaper'],
      ...(appUrl ? { click: appUrl } : {}),
    }, log);
    return { date: due };
  } catch (e) {
    log(`  Digest failed: ${e.message}`);
    return digestState;
  }
}
