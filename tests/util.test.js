const test = require("node:test");
const assert = require("node:assert");
const U = require("../src/util.js");
const rules = require("../rules/posture.json");

test("siteOf handles common suffixes and IPs", () => {
  assert.equal(U.siteOf("shop.example.com"), "example.com");
  assert.equal(U.siteOf("www.example.co.in"), "example.co.in");
  assert.equal(U.siteOf("a.b.example.co.uk"), "example.co.uk");
  assert.equal(U.siteOf("192.168.1.5"), "192.168.1.5");
  assert.equal(U.siteOf("localhost"), "localhost");
});

test("isThirdParty", () => {
  assert.equal(U.isThirdParty("cdn.example.com", "www.example.com"), false);
  assert.equal(U.isThirdParty("js.stripe.com", "www.example.com"), true);
});

test("version comparison and vulnerability ranges", () => {
  assert.equal(U.compareVersions("1.12.4", "3.5.0"), -1);
  assert.equal(U.compareVersions("3.5.0", "3.5.0"), 0);
  assert.equal(U.isVulnerableVersion("1.12.4", ["3.5.0"]), true);
  assert.equal(U.isVulnerableVersion("3.4.1", ["3.5.0"]), true);
  assert.equal(U.isVulnerableVersion("3.6.0", ["3.5.0"]), false);
  // Bootstrap has fixes on two branches
  assert.equal(U.isVulnerableVersion("3.3.7", ["3.4.1", "4.3.1"]), true);
  assert.equal(U.isVulnerableVersion("4.6.0", ["3.4.1", "4.3.1"]), false);
  assert.equal(U.isVulnerableVersion("5.3.0", ["3.4.1", "4.3.1"]), false);
  assert.equal(U.isVulnerableVersion("2.3.2", ["3.4.1", "4.3.1"]), true);
});

test("detectLibraries finds vulnerable and EOL libs, ignores safe ones", () => {
  const urls = [
    "https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js",
    "https://x.com/js/jquery-3.6.0.min.js",
    "https://x.com/angular.js/1.5.8/angular.min.js",
    "https://x.com/lodash.js/4.17.15/lodash.min.js",
    "https://x.com/jquery-ui-1.12.1.js",
    "https://x.com/app.js"
  ];
  const found = U.detectLibraries(urls, rules.libraries);
  const names = found.map((f) => f.name + "@" + f.version).sort();
  assert.deepEqual(names, ["AngularJS@1.5.8", "jQuery@1.12.4", "lodash@4.17.15"]);
});
