// talks to the /predict endpoint and shows the result on the page.

const BORDERLINE = 30; // score where "safe" starts looking suspicious

const el = (id) => document.getElementById(id);
const input  = el("url-input");
const btn    = el("analyze-btn");
const deep   = el("deep-scan");
const result = el("result");

async function analyze() {
  const url = input.value.trim();
  if (!url) {
    // little shake if the box is empty
    input.classList.add("shake");
    setTimeout(() => input.classList.remove("shake"), 400);
    return;
  }

  result.classList.remove("hidden");
  setVerdict("loading", "Analyzing...", url);
  setMeter(0, "var(--muted)");
  el("reasons").innerHTML = "";
  el("intel").innerHTML = "";
  el("inference").textContent = "";
  btn.disabled = true;
  result.scrollIntoView({ behavior: "smooth", block: "nearest" });

  try {
    const res = await fetch("/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url, enrich: deep.checked }),
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    render(await res.json());
  } catch (e) {
    setVerdict("error", "Couldn't analyze", url);
    el("inference").textContent = "Is the server running?";
  } finally {
    btn.disabled = false;
  }
}

function render(data) {
  const score = data.risk_score;

  // safe / suspicious / phishing
  let tier, label, color;
  if (data.is_phishing) {
    tier = "bad";  label = "Phishing";   color = "var(--bad)";
  } else if (score >= BORDERLINE) {
    tier = "warn"; label = "Suspicious";  color = "var(--warn)";
  } else {
    tier = "safe"; label = "Looks safe";  color = "var(--safe)";
  }

  setVerdict(tier, label, data.url);
  setMeter(score, color);
  el("risk-score").textContent = score;
  el("risk-level").textContent = data.risk_level;

  // reasons list
  const reasons = el("reasons");
  reasons.innerHTML = "";
  if (data.reasons && data.reasons.length) {
    data.reasons.forEach((r) => {
      const li = document.createElement("li");
      li.textContent = r;
      reasons.appendChild(li);
    });
  } else {
    const li = document.createElement("li");
    li.className = "none";
    li.textContent = "Nothing suspicious found.";
    reasons.appendChild(li);
  }

  showIntel(data.enrichment);

  el("inference").textContent =
    "Took " + Math.round(data.inference_ms) + " ms" +
    (data.enrichment ? " (deep scan)" : " (fast scan)");
}

function showIntel(enr) {
  const intel = el("intel");
  const panel = el("intel-panel");
  intel.innerHTML = "";

  // only show this panel if we actually did a deep scan
  if (!enr) { panel.style.display = "none"; return; }
  panel.style.display = "";

  const age = enr.domain_age_days;
  const rows = [
    ["Domain", enr.registrable_domain || enr.domain || "-"],
    ["Age", age == null ? "Unknown" : (age + " days (" + Math.floor(age / 365) + " yr)")],
    ["Created", enr.creation_date || "Unknown"],
    ["Registrar", enr.registrar || "Unknown"],
    ["Resolves (DNS)", enr.resolves === true ? "Yes" : enr.resolves === false ? "No" : "Unknown"],
  ];
  rows.forEach(([k, v]) => {
    const li = document.createElement("li");
    li.innerHTML = `<span class="k">${k}</span><span class="v">${v}</span>`;
    intel.appendChild(li);
  });
}

function setVerdict(tier, label, url) {
  const v = el("verdict");
  v.className = "verdict " + tier;
  el("verdict-label").textContent = label;
  el("verdict-url").textContent = url || "";
}

function setMeter(score, color) {
  const fill = el("meter-fill");
  fill.style.width = Math.max(2, Math.min(100, score)) + "%";
  fill.style.background = color;
}

btn.addEventListener("click", analyze);
input.addEventListener("keydown", (e) => { if (e.key === "Enter") analyze(); });

// example buttons: fill the box and run it
document.querySelectorAll(".chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    input.value = chip.dataset.url;
    analyze();
  });
});
