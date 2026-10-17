// Pure classification logic. No browser APIs, so it can be unit tested in Node.
// Loaded in the service worker via importScripts().

const _cU = typeof module !== "undefined" ? require("./util.js") : globalThis;

function findGateway(rules, host, field) {
  return rules.gateways.find((g) => _cU.matchesDomain(host, g[field])) || null;
}

/**
 * @param {object} rules   parsed rules/gateways.json
 * @param {string} pageHost hostname of the top-level page
 * @param {object} signals  { iframeHosts[], scriptHosts[], cardFieldOnPage, upiLinks }
 * @returns {{ class: string, gateway: string|null, confidence: string, evidence: string[] }}
 */
function classify(rules, pageHost, signals) {
  const evidence = [];

  // 1. We are ON a gateway's own domain -> hosted payment page.
  const hosted = findGateway(rules, pageHost, "hostedDomains");
  if (hosted) {
    evidence.push(`Page is served from ${pageHost}, a ${hosted.name} hosted domain`);
    return { class: "hosted", gateway: hosted.name, confidence: "high", evidence };
  }

  // 2. Gateway iframe or SDK script on the merchant page -> API-hosted.
  let frameGw = null;
  for (const h of signals.iframeHosts || []) {
    const g = findGateway(rules, h, "frameDomains");
    if (g) { frameGw = g; evidence.push(`Iframe from ${h} (${g.name})`); break; }
  }
  let scriptGw = null;
  for (const h of signals.scriptHosts || []) {
    const g = findGateway(rules, h, "scriptDomains");
    if (g) { scriptGw = g; evidence.push(`Script from ${h} (${g.name})`); break; }
  }
  if (frameGw) {
    return { class: "api-hosted", gateway: frameGw.name, confidence: "high", evidence };
  }
  if (scriptGw) {
    const note = signals.cardFieldOnPage
      ? "Card field present alongside gateway SDK"
      : "No card field on this page; checkout may redirect to a hosted page";
    evidence.push(note);
    return {
      class: "api-hosted",
      gateway: scriptGw.name,
      confidence: signals.cardFieldOnPage ? "medium" : "low",
      evidence,
    };
  }

  // 3. Card field on the merchant's own page with no gateway components -> self-hosted.
  if (signals.cardFieldOnPage) {
    evidence.push("Card number field on the page with no known gateway iframe or SDK");
    return { class: "self-hosted", gateway: null, confidence: "medium", evidence };
  }

  // 4. UPI intent links -> payment happens outside the site.
  if (signals.upiLinks > 0) {
    evidence.push(`${signals.upiLinks} UPI deep link(s) (upi://) on the page`);
    return { class: "off-website", gateway: null, confidence: "low", evidence };
  }

  return { class: "none", gateway: null, confidence: "n/a", evidence: ["No payment signals found"] };
}

if (typeof module !== "undefined") module.exports = { classify, matchesDomain: _cU.matchesDomain };
