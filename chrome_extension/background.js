/*
  background.js  (the "service worker")
  -------------------------------------
  Runs quietly in the background. Every time you finish loading a page, this:
    1. Sends the page's URL to your Phishinobi API (fast scan, no WHOIS).
    2. Sets a BADGE on the toolbar icon:  green ✓ = safe,  red ! = phishing.
    3. If it's phishing, tells content.js to draw a red warning bar on the page.

  This is what makes Phishinobi automatic — you no longer click anything.
  We use enrich=false here (fast, offline-style) so browsing stays snappy and
  we don't hammer WHOIS. The popup still offers the slower "Deep scan" on demand.
*/

const API_URL = "http://127.0.0.1:8000/predict";
const BORDERLINE = 30; // fast-scan score at/above which we auto-run a deep scan

// One call to the API.
async function callApi(url, enrich) {
  const res = await fetch(API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, enrich }),
  });
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

// The shared brain: fast scan first, then ESCALATE to a deep WHOIS/DNS scan if
// the result is borderline (looks safe but scores suspiciously high). Used by
// BOTH the page auto-check and the hover-to-check feature, so they always
// agree. Throws if the API is unreachable.
async function analyzeUrl(url) {
  let data = await callApi(url, false); // fast, text-only
  if (!data.is_phishing && data.risk_score >= BORDERLINE) {
    try {
      data = await callApi(url, true);  // deep scan to be sure
    } catch (e) {
      /* deep scan failed (e.g. WHOIS timeout) — keep the fast result */
    }
  }
  return data;
}

// Remember URLs we've already warned about so we don't open a new warning tab
// every time a page re-fires its "complete" event. Key = url, value = time.
const recentlyWarned = new Map();
// Short cooldown: just long enough to swallow the duplicate "complete" events
// a single page load can fire, but short enough that genuinely revisiting a
// bad site warns you again.
const WARN_COOLDOWN_MS = 8 * 1000; // 8 seconds

function openWarningTab(siteUrl, data) {
  const now = Date.now();
  const last = recentlyWarned.get(siteUrl);
  if (last && now - last < WARN_COOLDOWN_MS) return; // already warned recently
  recentlyWarned.set(siteUrl, now);

  const warnUrl =
    chrome.runtime.getURL("warning.html") +
    "?site=" + encodeURIComponent(siteUrl) +
    "&score=" + encodeURIComponent(data.risk_score) +
    "&reasons=" + encodeURIComponent((data.reasons || []).join("||"));

  chrome.tabs.create({ url: warnUrl });
}

async function checkTab(tabId, url) {
  // Only analyze real web pages — skip chrome://, about:blank, etc.
  if (!url || !/^https?:\/\//i.test(url)) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  try {
    const data = await analyzeUrl(url); // fast scan + auto-escalation

    if (data.is_phishing) {
      // Red badge.
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#dc2626" });
      chrome.action.setBadgeText({ tabId, text: "!" });

      // (0) The can't-miss alert: open a full-page red warning in a new tab.
      //     Chrome fully controls this, so Windows settings can't hide it.
      openWarningTab(url, data);

      // (1) Desktop notification — works EVERYWHERE, even on dead/error pages.
      //     Using the URL as the notification id means re-loading the same
      //     page replaces the alert instead of stacking duplicates.
      chrome.notifications.create(url, {
        type: "basic",
        iconUrl: chrome.runtime.getURL("icon128.png"),
        title: "🚨 Phishing site detected!",
        message:
          "Risk " + data.risk_score + "/100. Do NOT enter passwords or card details.\n" +
          (data.reasons && data.reasons[0] ? "• " + data.reasons[0] : ""),
        priority: 2,
        requireInteraction: true, // stay on screen until dismissed
      }, (id) => {
        // If Chrome itself rejected it, this logs why (visible in the service
        // worker console). If there's NO error here but you still see nothing,
        // the cause is Windows suppressing it (notification settings / focus).
        if (chrome.runtime.lastError) {
          console.error("Phishinobi notification error:", chrome.runtime.lastError.message);
        } else {
          console.log("Phishinobi notification created, id:", id);
        }
      });

      // (2) Also try the on-page red bar (works only if the page actually
      //     loaded — harmless if it didn't). The lastError check swallows the
      //     "no receiver" noise on error pages.
      chrome.tabs.sendMessage(tabId, { action: "phishingWarning", data }, () => {
        void chrome.runtime.lastError;
      });
    } else {
      // Green badge, no banner.
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#16a34a" });
      chrome.action.setBadgeText({ tabId, text: "✓" }); // ✓
    }
  } catch (e) {
    // Gray "?" badge = couldn't reach the API (server probably not running).
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#6b7280" });
    chrome.action.setBadgeText({ tabId, text: "?" });
  }
}

// Fire whenever a tab finishes loading a page.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    checkTab(tabId, tab.url);
  }
});

// ── Hover feature: answer "check this URL" requests from hover.js ──────────
// Content scripts inside Gmail can't call the local API directly (the page's
// security policy blocks it). So they ask US (the background worker) to do it,
// and we send the verdict back. Uses the same analyzeUrl() as the page check,
// so a borderline link gets the deep scan and the tooltip stays accurate.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.action === "checkUrl" && msg.url) {
    // hover.js asks for a fast scan first (deep:false) for an instant tooltip,
    // then a deep scan (deep:true) only for borderline links, to upgrade it.
    callApi(msg.url, msg.deep === true)
      .then((data) => sendResponse({ ok: true, data }))
      .catch((err) => sendResponse({ ok: false, error: String(err) }));
    return true; // keep the message channel open for the async response
  }
});
