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

/**
 * Send alerts for the given candidates and record them in `alerted` (story id -> ISO time).
 * Never throws: alerts must not break the briefing.
 */
export async function sendAlerts({ candidates, alerted, alertState, appUrl, log }) {
  const topic = process.env.NTFY_TOPIC?.trim();
  if (!topic) return alertState;
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
        click: lead.url,
        actions: [
          { action: 'view', label: `Read on ${lead.name}`.slice(0, 40), url: lead.url },
          ...(appUrl ? [{ action: 'view', label: 'Open CyberBrief', url: appUrl }] : []),
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
