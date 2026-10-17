const test = require("node:test");
const assert = require("node:assert");
const { analyze, parseClient, cspAssessment } = require("../src/analyzer.js");
const rules = require("../rules/posture.json");
const gateways = require("../rules/gateways.json");

const NOW = Date.parse("2026-10-20");
const goodHeaders = {
  "strict-transport-security": "max-age=31536000",
  "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-abc' https://js.stripe.com; frame-ancestors 'self'"
};
const modernClient = { source: "uaData", browser: "Google Chrome", chromiumMajor: 155, os: "Windows", osVersion: "15.0.0", osMajor: 15, mobile: false };

function run(over = {}) {
  return analyze({
    rules, gateways, now: NOW,
    classification: { class: "api-hosted", gateway: "Stripe", confidence: "high", host: "shop.example.com" },
    signals: { pageScheme: "https:", scriptItems: [], cardForms: [], mixedCount: 0 },
    headers: goodHeaders,
    client: modernClient,
    ...over
  });
}
const ids = (r) => r.findings.map((f) => f.id);

test("no payment flow -> not applicable", () => {
  const r = run({ classification: { class: "none", confidence: "n/a", host: "x.com" } });
  assert.equal(r.applicable, false);
  assert.equal(r.score, null);
});

test("clean api-hosted page scores at baseline", () => {
  const r = run();
  assert.equal(r.score, 82);
  assert.equal(r.grade, "B");
  assert.deepEqual(ids(r), ["gw-context"]);
});

test("hosted baseline is higher than self-hosted", () => {
  const h = run({ classification: { class: "hosted", gateway: "Stripe", confidence: "high", host: "checkout.stripe.com" } });
  const s = run({ classification: { class: "self-hosted", gateway: null, confidence: "medium", host: "shop.example.com" } });
  assert.ok(h.score > s.score);
});

test("plain HTTP page is critical", () => {
  const r = run({ signals: { pageScheme: "http:", scriptItems: [], cardForms: [] }, headers: null });
  assert.ok(ids(r).includes("tls-none"));
  assert.equal(r.findings[0].severity, "critical");
  assert.equal(r.providerPenalty, 30);
});

test("missing CSP is high on payment pages, medium on hosted", () => {
  const noCsp = { "strict-transport-security": "max-age=1", "x-frame-options": "DENY" };
  const a = run({ headers: noCsp });
  assert.equal(a.findings.find((f) => f.id === "csp-missing").severity, "high");
  const h = run({ headers: noCsp, classification: { class: "hosted", gateway: "Stripe", confidence: "high", host: "checkout.stripe.com" } });
  assert.equal(h.findings.find((f) => f.id === "csp-missing").severity, "medium");
});

test("CSP assessment", () => {
  assert.equal(cspAssessment("").present, false);
  assert.equal(cspAssessment("script-src 'self' 'unsafe-inline'").weak, true);
  assert.equal(cspAssessment("script-src 'self' 'unsafe-inline' 'nonce-xyz'").weak, false);
  assert.equal(cspAssessment("script-src *").weak, true);
  assert.equal(cspAssessment("frame-ancestors 'none'").weak, true); // does not restrict scripts
  assert.equal(cspAssessment("default-src 'self'; frame-ancestors 'none'").frameAncestors, true);
});

test("missing headers produce info, not penalties", () => {
  const r = run({ headers: null });
  assert.ok(ids(r).includes("meta-no-headers"));
  assert.equal(r.providerPenalty, 0);
});

test("mixed content and insecure card form", () => {
  const r = run({ signals: { pageScheme: "https:", scriptItems: [], mixedCount: 2, cardForms: [{ scheme: "http:", host: "shop.example.com" }] } });
  assert.ok(ids(r).includes("mixed-content"));
  assert.ok(ids(r).includes("form-http-0"));
});

test("card form to unknown domain is flagged, to a gateway is not", () => {
  const bad = run({ signals: { pageScheme: "https:", scriptItems: [], mixedCount: 0, cardForms: [{ scheme: "https:", host: "collect.evil.io" }] } });
  assert.ok(ids(bad).includes("form-xdomain-0"));
  const ok = run({ signals: { pageScheme: "https:", scriptItems: [], mixedCount: 0, cardForms: [{ scheme: "https:", host: "api.razorpay.com" }] } });
  assert.ok(!ids(ok).includes("form-xdomain-0"));
});

test("third-party script thresholds are stricter on payment pages and exclude gateway SDKs", () => {
  const mk = (n) => Array.from({ length: n }, (_, i) => ({ url: `https://t${i}.tracker${i}.com/a.js`, host: `t${i}.tracker${i}.com`, sri: true }));
  const sdk = { url: "https://js.stripe.com/v3/", host: "js.stripe.com", sri: false };
  const r = run({ signals: { pageScheme: "https:", scriptItems: [...mk(3), sdk], mixedCount: 0, cardForms: [] } });
  assert.ok(ids(r).includes("third-party-some"));
  assert.ok(!ids(r).includes("sri-missing")); // SDK excluded
  const hosted = run({ classification: { class: "hosted", gateway: "Stripe", confidence: "high", host: "checkout.stripe.com" },
    signals: { pageScheme: "https:", scriptItems: mk(3), mixedCount: 0, cardForms: [] } });
  assert.ok(!ids(hosted).includes("third-party-some"));
});

test("outdated library is flagged with mapping", () => {
  const r = run({ signals: { pageScheme: "https:", mixedCount: 0, cardForms: [],
    scriptItems: [{ url: "https://x.com/jquery-1.12.4.min.js", host: "shop.example.com", sri: false }] } });
  const f = r.findings.find((x) => x.id === "lib-jquery");
  assert.ok(f);
  assert.ok(f.attack.includes("T1189"));
  assert.ok(f.pci.some((p) => p.includes("6.3.3")));
});

test("penalties are capped and score floors at 0", () => {
  const r = run({
    classification: { class: "self-hosted", gateway: null, confidence: "medium", host: "shop.example.com" },
    signals: { pageScheme: "http:", scriptItems: [], cardForms: [] }, headers: null,
    client: { ...modernClient, chromiumMajor: 120 }
  });
  assert.ok(r.providerPenalty <= rules.caps.provider);
  assert.ok(r.clientPenalty <= rules.caps.client);
  assert.ok(r.score >= 0);
});

test("client: old browser and Windows 10 are flagged; modern is clean", () => {
  const old = run({ client: { ...modernClient, chromiumMajor: 140, osMajor: 10 } });
  assert.ok(ids(old).includes("client-browser-old"));
  assert.ok(ids(old).includes("client-os-win10"));
  const behind = run({ client: { ...modernClient, chromiumMajor: 150 } });
  assert.ok(ids(behind).includes("client-browser-behind"));
  assert.ok(!ids(run()).some((i) => i.startsWith("client-")));
});

test("stale rules skip version checks instead of guessing", () => {
  const r = run({ now: Date.parse("2027-06-01"), client: { ...modernClient, chromiumMajor: 100 } });
  assert.ok(ids(r).includes("meta-stale-rules"));
  assert.ok(!ids(r).includes("client-browser-old"));
});

test("ATT&CK roll-up lists techniques from non-info findings", () => {
  const r = run({ headers: { "strict-transport-security": "max-age=1", "x-frame-options": "DENY" } });
  const t = r.techniques.map((x) => x.id);
  assert.ok(t.includes("T1059.007"));
  assert.ok(r.techniques.every((x) => x.name));
});

test("parseClient from userAgentData and from UA fallback", () => {
  const c = parseClient({ platform: "Windows", mobile: false, platformVersion: "15.0.0",
    fullVersionList: [{ brand: "Not A;Brand", version: "8.0.0.0" }, { brand: "Chromium", version: "155.0.8059.39" }, { brand: "Google Chrome", version: "155.0.8059.39" }] }, "");
  assert.equal(c.chromiumMajor, 155);
  assert.equal(c.osMajor, 15);
  assert.equal(c.browser, "Google Chrome");
  const u = parseClient(null, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/150.0.0.0 Safari/537.36");
  assert.equal(u.source, "ua");
  assert.equal(u.chromiumMajor, 150);
  assert.equal(u.osMajor, null);
});
