/*
  warning.js
  ----------
  Fills in the warning page using info passed in the URL's query string, e.g.
  warning.html?site=...&score=63&reasons=reason1||reason2
  Background.js builds that link when it detects phishing.
*/

const params = new URLSearchParams(location.search);

const site = params.get("site") || "(unknown site)";
const score = params.get("score") || "?";
const reasons = (params.get("reasons") || "").split("||").filter(Boolean);

document.getElementById("site").textContent = site;
document.getElementById("score").textContent = score;

const list = document.getElementById("reasons");
if (reasons.length === 0) {
  list.style.display = "none";
} else {
  reasons.forEach((r) => {
    const li = document.createElement("li");
    li.textContent = r;
    list.appendChild(li);
  });
}

// "Get me out" → close this warning tab and go back to safety.
document.getElementById("back").addEventListener("click", () => {
  // Try to navigate this tab to a safe place, then it can be closed.
  chrome.tabs.getCurrent((tab) => {
    if (tab) chrome.tabs.remove(tab.id);
  });
});

// "Ignore" → just close the warning tab (the original site stays open).
document.getElementById("ignore").addEventListener("click", () => {
  chrome.tabs.getCurrent((tab) => {
    if (tab) chrome.tabs.remove(tab.id);
  });
});
