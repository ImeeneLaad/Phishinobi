/*
  popup.js
  --------
  The logic behind the popup. Flow:
    1. Find the URL of the tab you're currently on.
    2. Send it to your local Phishinobi API (POST /predict).
    3. Paint the result (safe / phishing / error) into the popup.

  The extension does NO detection itself — it just asks the API you built.
*/

const API_URL = "http://127.0.0.1:8000/predict";

// Grab references to the page elements we'll update.
const els = {
  url:        document.getElementById("url-box"),
  verdict:    document.getElementById("verdict"),
  icon:       document.getElementById("verdict-icon"),
  label:      document.getElementById("verdict-label"),
  risk:       document.getElementById("risk"),
  riskScore:  document.getElementById("risk-score"),
  riskLevel:  document.getElementById("risk-level"),
  reasonsWrap:document.getElementById("reasons-wrap"),
  reasons:    document.getElementById("reasons"),
  deepScan:   document.getElementById("deep-scan"),
  recheck:    document.getElementById("recheck"),
  footer:     document.getElementById("footer"),
};

// ---- helpers to switch the banner's look ----
function setVerdict(modifier, icon, label) {
  els.verdict.className = "verdict verdict--" + modifier;
  els.icon.textContent = icon;
  els.label.textContent = label;
}

function showError(message) {
  setVerdict("error", "⚠️", "Couldn't check");
  els.footer.textContent = message;
  els.risk.classList.add("hidden");
  els.reasonsWrap.classList.add("hidden");
}

// ---- get the current tab's URL ----
async function getCurrentUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab ? tab.url : null;
}

// ---- the main routine ----
async function checkCurrentTab() {
  // Reset to loading state.
  setVerdict("loading", "⏳", "Analyzing…");
  els.risk.classList.add("hidden");
  els.reasonsWrap.classList.add("hidden");
  els.footer.textContent = "Talking to Phishinobi API…";

  const url = await getCurrentUrl();
  els.url.textContent = url || "(no URL)";

  // Chrome's own pages (chrome://, extension pages, etc.) can't be analyzed.
  if (!url || !/^https?:\/\//i.test(url)) {
    showError("This isn't a normal web page (can't analyze chrome:// or blank tabs).");
    return;
  }

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url, enrich: els.deepScan.checked }),
    });

    if (!response.ok) {
      showError("API returned an error (HTTP " + response.status + ").");
      return;
    }

    const data = await response.json();
    renderResult(data);
  } catch (err) {
    // Most common cause: the API server isn't running.
    showError("Can't reach the API. Is the server running? (uvicorn on port 8000)");
  }
}

// ---- paint the verdict ----
function renderResult(data) {
  if (data.is_phishing) {
    setVerdict("phishing", "🚨", "PHISHING");
  } else {
    setVerdict("safe", "✅", "SAFE");
  }

  els.riskScore.textContent = data.risk_score;
  els.riskLevel.textContent = data.risk_level;
  els.risk.classList.remove("hidden");

  // List the reasons (if any).
  els.reasons.innerHTML = "";
  if (data.reasons && data.reasons.length > 0) {
    data.reasons.forEach((r) => {
      const li = document.createElement("li");
      li.textContent = r;
      els.reasons.appendChild(li);
    });
    els.reasonsWrap.classList.remove("hidden");
  } else {
    els.reasonsWrap.classList.add("hidden");
  }

  const mode = els.deepScan.checked ? "deep scan (WHOIS+DNS)" : "fast scan";
  els.footer.textContent = "Checked via " + mode + ".";
}

// ---- wire up events ----
document.addEventListener("DOMContentLoaded", checkCurrentTab);
els.recheck.addEventListener("click", checkCurrentTab);
els.deepScan.addEventListener("change", checkCurrentTab);  // re-run when toggled
