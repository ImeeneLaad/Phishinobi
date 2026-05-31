/*
  hover.js
  --------
  Hover-to-check links. When you rest your mouse on a link for ~0.3s, this
  shows a small tooltip telling you whether the link's DESTINATION is safe or
  phishing — before you ever click.

  Two-phase tooltip (so it feels instant but stays accurate):
    Phase 1 — FAST scan → show a verdict immediately:
                ✅ Safe        (low score)
                ⚠️ Suspicious  (borderline: looks risky but under the line)
                🚨 Phishing    (model is sure)
    Phase 2 — for borderline links only, quietly run a DEEP (WHOIS/DNS) scan
                and UPGRADE the tooltip to the final verdict when it returns.

  Other pieces:
    • unwrapRedirect() — emails wrap links (google.com/url?q=...); we dig out
                         the real target.
    • 300ms debounce   — only check after you pause on a link.
    • cache            — each link's final verdict is remembered (instant re-hover).
    • messaging        — background.js makes the actual API calls (content
                         scripts inside Gmail are blocked from calling it).
*/

(() => {
  const BORDERLINE = 30;          // score at/above which we deep-scan to be sure
  const cache = new Map();        // resolvedUrl -> final verdict data
  let hoverTimer = null;
  let currentTarget = null;       // the link we're currently showing a tip for
  let mouseX = 0, mouseY = 0;

  // ---- the floating tooltip element ----
  const tip = document.createElement("div");
  tip.style.cssText = [
    "position:fixed", "z-index:2147483647", "pointer-events:none",
    "padding:6px 10px", "border-radius:6px", "font-size:12px",
    "font-family:'Segoe UI',system-ui,sans-serif", "font-weight:600",
    "box-shadow:0 2px 10px rgba(0,0,0,.35)", "max-width:340px",
    "display:none", "color:#fff",
  ].join(";");
  document.documentElement.appendChild(tip);

  // Each tier: [background, text color]. Yellow needs dark text to stay readable.
  const COLORS = {
    loading:    ["#334155", "#ffffff"],
    safe:       ["#16a34a", "#ffffff"],
    suspicious: ["#facc15", "#1f2937"],   // bright yellow, dark text
    phishing:   ["#dc2626", "#ffffff"],
    error:      ["#b45309", "#ffffff"],
  };

  function showTip(text, kind) {
    const [bg, fg] = COLORS[kind] || COLORS.loading;
    tip.textContent = text;
    tip.style.background = bg;
    tip.style.color = fg;
    tip.style.display = "block";
    positionTip();
  }
  function hideTip() { tip.style.display = "none"; }

  function positionTip() {
    const pad = 14;
    let x = mouseX + pad, y = mouseY + pad;
    const rect = tip.getBoundingClientRect();
    if (x + rect.width > window.innerWidth)  x = mouseX - rect.width - pad;
    if (y + rect.height > window.innerHeight) y = mouseY - rect.height - pad;
    tip.style.left = Math.max(0, x) + "px";
    tip.style.top  = Math.max(0, y) + "px";
  }

  // Decide which tier a verdict falls into and show it.
  function renderFinal(target, data) {
    if (target !== currentTarget) return; // user moved to another link; ignore
    const score = data.risk_score;
    if (data.is_phishing) {
      showTip("🚨 PHISHING — risk " + score + "/100", "phishing");
    } else if (score >= BORDERLINE) {
      showTip("⚠️ Suspicious — risk " + score + "/100", "suspicious");
    } else {
      showTip("✅ Safe — risk " + score + "/100", "safe");
    }
  }

  // ---- unwrap email/redirect links to find the true destination ----
  function unwrapRedirect(href) {
    try {
      const u = new URL(href, location.href);
      if (u.hostname.endsWith("google.com") && (u.pathname === "/url" || u.pathname === "/visit")) {
        const real = u.searchParams.get("q") || u.searchParams.get("url");
        if (real) return real;
      }
      if (u.hostname.includes("safelinks.protection.outlook.com")) {
        const real = u.searchParams.get("url");
        if (real) return real;
      }
      const generic = u.searchParams.get("url") || u.searchParams.get("u");
      if (generic && /^https?:\/\//i.test(generic)) return generic;
      return href;
    } catch (e) {
      return href;
    }
  }

  // ---- the two-phase check ----
  function check(target) {
    // Instant if we've already resolved this link before.
    if (cache.has(target)) { renderFinal(target, cache.get(target)); return; }

    showTip("⏳ Checking link…", "loading");

    // Phase 1: fast scan.
    chrome.runtime.sendMessage({ action: "checkUrl", url: target, deep: false }, (resp) => {
      if (chrome.runtime.lastError) { showTip("⚠️ Phishinobi API offline", "error"); return; }
      if (!resp || !resp.ok)        { showTip("⚠️ Couldn't check link", "error"); return; }

      const fast = resp.data;
      const borderline = !fast.is_phishing && fast.risk_score >= BORDERLINE;

      if (!borderline) {
        cache.set(target, fast);          // confident either way — done
        renderFinal(target, fast);
        return;
      }

      // Borderline: show the suspicious verdict NOW, then deep-scan to upgrade.
      if (target === currentTarget) {
        showTip("⚠️ Suspicious — risk " + fast.risk_score + "/100 · double-checking…", "suspicious");
      }

      // Phase 2: deep scan (WHOIS/DNS). May take a few seconds.
      chrome.runtime.sendMessage({ action: "checkUrl", url: target, deep: true }, (resp2) => {
        const finalData = (resp2 && resp2.ok) ? resp2.data : fast; // fall back to fast
        cache.set(target, finalData);
        renderFinal(target, finalData);
      });
    });
  }

  // ---- event wiring ----
  document.addEventListener("mousemove", (e) => {
    mouseX = e.clientX; mouseY = e.clientY;
    if (tip.style.display === "block") positionTip();
  });

  document.addEventListener("mouseover", (e) => {
    const a = e.target.closest ? e.target.closest("a[href]") : null;
    if (!a) return;

    const target = unwrapRedirect(a.href);
    if (!/^https?:\/\//i.test(target)) return; // skip mailto:, javascript:, #anchors

    clearTimeout(hoverTimer);
    hoverTimer = setTimeout(() => {
      currentTarget = target;
      check(target);
    }, 300);
  });

  document.addEventListener("mouseout", (e) => {
    const a = e.target.closest ? e.target.closest("a[href]") : null;
    if (a) {
      clearTimeout(hoverTimer);
      currentTarget = null;
      hideTip();
    }
  });
})();
