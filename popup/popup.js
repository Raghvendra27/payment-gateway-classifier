const app = document.getElementById("app");

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

async function loadJson(path) {
  return (await fetch(chrome.runtime.getURL(path))).json();
}

async function getClient() {
  let hi = null;
  try {
    if (navigator.userAgentData) {
      hi = await navigator.userAgentData.getHighEntropyValues(["platformVersion", "fullVersionList"]);
    }
  } catch (e) {}
  return parseClient(hi, navigator.userAgent);
}

function render(result, client, host) {
  app.textContent = "";

  const top = el("div", "row");
  top.append(el("span", "chip", result.class), el("strong", "", result.gateway || "no known gateway"));
  top.append(el("span", "muted", "confidence: " + result.confidence));
  app.append(top);

  if (!result.applicable) {
    app.append(el("p", "", "No payment flow detected on this page. Go to the checkout or payment step and open the extension again."));
    return;
  }

  // Score
  const s = el("div", "row");
  s.style.marginTop = "12px";
  s.append(el("span", "score", String(result.score)), el("span", "grade grade-" + result.grade, result.grade));
  const meta = el("div");
  meta.append(el("div", "", "Security score (higher is safer)"));
  if (result.provisional) meta.append(el("div", "muted", "Provisional: classification confidence is low"));
  s.append(meta);
  app.append(s);
  app.append(el("div", "breakdown muted",
    `Baseline ${result.baseline} · provider −${result.providerPenalty} · client −${result.clientPenalty}`));

  // Findings
  app.append(el("h2", "", "Findings"));
  const list = el("div", "findings");
  result.findings.forEach((f) => {
    const d = document.createElement("details");
    const sum = document.createElement("summary");
    sum.append(el("span", "sev sev-" + f.severity, f.severity), el("span", "", f.title));
    d.append(sum);
    const body = el("div", "detail");
    if (f.detail) body.append(el("div", "", f.detail));
    if (f.fix) body.append(el("div", "muted", "Fix: " + f.fix));
    const tags = el("div");
    f.attack.forEach((id) => tags.append(el("span", "tag", "ATT&CK " + id)));
    f.pci.forEach((p) => tags.append(el("span", "tag", p.replace("PCI DSS v4.0 ", "PCI "))));
    f.cwe.forEach((c) => tags.append(el("span", "tag", c)));
    body.append(tags);
    d.append(body);
    list.append(d);
  });
  app.append(list);

  // ATT&CK roll-up
  if (result.techniques.length) {
    app.append(el("h2", "", "MITRE ATT&CK techniques"));
    const t = el("div");
    result.techniques.forEach((x) => t.append(el("span", "tag", x.id + " " + x.name)));
    app.append(t);
  }

  // Client
  app.append(el("h2", "", "This device"));
  const bits = [client.browser, client.chromiumMajor ? "v" + client.chromiumMajor : null, client.os,
    client.osVersion ? client.osVersion : null].filter(Boolean);
  app.append(el("div", "muted", bits.length ? bits.join(" · ") : "Not available"));

  // Export
  const btn = el("button", "", "Copy report (JSON)");
  btn.addEventListener("click", async () => {
    const report = { tool: "payment-gateway-classifier", version: chrome.runtime.getManifest().version,
      generatedAt: new Date().toISOString(), host, client, result };
    await navigator.clipboard.writeText(JSON.stringify(report, null, 2));
    btn.textContent = "Copied";
  });
  app.append(btn);
  app.append(el("div", "disclaimer",
    "Indicative score from passive checks. It is not a PCI compliance determination or a penetration test."));
}

(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) { app.textContent = "No active tab."; return; }
  let host = "";
  try { host = new URL(tab.url).hostname; } catch (e) {}

  const tabKey = "tab:" + tab.id;
  const hdrKey = "hdr:" + tab.id;
  const stored = await chrome.storage.session.get([tabKey, hdrKey]);
  const data = stored[tabKey];
  if (!data || data.host !== host) {
    app.textContent = "No data yet for this page. Reload it and reopen.";
    return;
  }
  const hdr = stored[hdrKey];
  const [rules, gateways, client] = await Promise.all([
    loadJson("rules/posture.json"), loadJson("rules/gateways.json"), getClient()
  ]);

  const result = analyze({
    rules, gateways,
    classification: data,
    signals: data.signals,
    headers: hdr && hdr.host === host ? hdr.headers : null,
    client,
    now: Date.now()
  });
  render(result, client, host);
})();
