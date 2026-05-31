/*
  content.js
  ----------
  This script is injected into every web page you visit. It does nothing on
  its own — it just WAITS for a message from background.js. When background.js
  decides a page is phishing, it sends "phishingWarning" and this script draws
  a big red warning bar at the top of the page.

  Why a separate script: only code running *inside the page* can modify what
  you see on that page. The background worker can't touch the page directly.
*/

chrome.runtime.onMessage.addListener((msg) => {
  if (msg && msg.action === "phishingWarning") {
    showBanner(msg.data);
  }
});

function showBanner(data) {
  // Don't add the bar twice.
  if (document.getElementById("phishinobi-banner")) return;

  const bar = document.createElement("div");
  bar.id = "phishinobi-banner";
  bar.style.cssText = [
    "position:fixed", "top:0", "left:0", "right:0",
    "z-index:2147483647",                 // sit above everything on the page
    "background:#7f1d1d", "color:#fff",
    "font-family:'Segoe UI',system-ui,sans-serif",
    "font-size:14px", "padding:12px 16px",
    "box-shadow:0 2px 10px rgba(0,0,0,.45)",
    "display:flex", "align-items:center", "gap:12px",
  ].join(";");

  const text = document.createElement("div");
  text.style.flex = "1";
  const score = (data && typeof data.risk_score === "number") ? data.risk_score : "?";
  text.innerHTML =
    "🚨 <strong>Phishinobi warning:</strong> this page looks like a phishing site " +
    "(risk " + score + "/100). Do <strong>not</strong> enter passwords, card numbers, or personal info.";

  const close = document.createElement("button");
  close.textContent = "Dismiss";
  close.style.cssText =
    "background:#fff;color:#7f1d1d;border:none;border-radius:4px;" +
    "padding:6px 12px;cursor:pointer;font-weight:700;white-space:nowrap;";
  close.addEventListener("click", () => bar.remove());

  bar.appendChild(text);
  bar.appendChild(close);
  // documentElement works even before <body> exists.
  document.documentElement.appendChild(bar);
}
