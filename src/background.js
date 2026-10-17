importScripts("util.js", "classifier.js");

let rulesPromise = null;
function loadRules() {
  if (!rulesPromise) {
    rulesPromise = fetch(chrome.runtime.getURL("rules/gateways.json")).then((r) => r.json());
  }
  return rulesPromise;
}

const BADGE = { hosted: "H", "api-hosted": "A", "self-hosted": "S", "off-website": "U", none: "" };
const COLORS = { hosted: "#2e7d32", "api-hosted": "#1565c0", "self-hosted": "#c62828", "off-website": "#6a1b9a" };

// 1) Signals from the page -> classification, stored per tab.
chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg.type !== "signals" || !sender.tab || sender.frameId !== 0) return;
  const tabId = sender.tab.id;
  loadRules().then((rules) => {
    const result = classify(rules, msg.host, msg.signals);
    result.host = msg.host;
    result.pageUrl = msg.pageUrl;
    result.signals = msg.signals;
    chrome.storage.session.set({ ["tab:" + tabId]: result });
    chrome.action.setBadgeText({ tabId, text: BADGE[result.class] || "" });
    if (COLORS[result.class]) chrome.action.setBadgeBackgroundColor({ tabId, color: COLORS[result.class] });
  });
});

// 2) Response headers of the top-level page (observed only, never modified).
const WANTED_HEADERS = new Set([
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "server",
  "x-powered-by"
]);

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const headers = {};
    for (const h of details.responseHeaders || []) {
      const name = h.name.toLowerCase();
      if (WANTED_HEADERS.has(name)) {
        headers[name] = headers[name] ? headers[name] + ", " + h.value : h.value;
      }
    }
    let host = "";
    try { host = new URL(details.url).hostname; } catch (e) {}
    chrome.storage.session.set({ ["hdr:" + details.tabId]: { host, status: details.statusCode, headers } });
  },
  { urls: ["http://*/*", "https://*/*"], types: ["main_frame"] },
  ["responseHeaders"]
);

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove(["tab:" + tabId, "hdr:" + tabId]);
});
