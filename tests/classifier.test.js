const test = require("node:test");
const assert = require("node:assert");
const { classify } = require("../src/classifier.js");
const rules = require("../rules/gateways.json");

const base = { iframeHosts: [], scriptHosts: [], cardFieldOnPage: false, upiLinks: 0 };

test("on a gateway domain -> hosted", () => {
  const r = classify(rules, "checkout.stripe.com", base);
  assert.equal(r.class, "hosted");
  assert.equal(r.gateway, "Stripe");
});

test("gateway iframe on merchant page -> api-hosted, high", () => {
  const r = classify(rules, "shop.example.com", { ...base, iframeHosts: ["js.stripe.com"] });
  assert.equal(r.class, "api-hosted");
  assert.equal(r.confidence, "high");
});

test("gateway script only -> api-hosted, low", () => {
  const r = classify(rules, "shop.example.com", { ...base, scriptHosts: ["checkout.razorpay.com"] });
  assert.equal(r.class, "api-hosted");
  assert.equal(r.confidence, "low");
});

test("card field with no gateway -> self-hosted", () => {
  const r = classify(rules, "shop.example.com", { ...base, cardFieldOnPage: true });
  assert.equal(r.class, "self-hosted");
});

test("upi links -> off-website", () => {
  const r = classify(rules, "shop.example.com", { ...base, upiLinks: 2 });
  assert.equal(r.class, "off-website");
});

test("nothing -> none", () => {
  assert.equal(classify(rules, "example.com", base).class, "none");
});

test("lookalike domain does not match", () => {
  const r = classify(rules, "shop.example.com", { ...base, iframeHosts: ["js.stripe.com.evil.io"] });
  assert.equal(r.class, "none");
});
