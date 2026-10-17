// Shared helpers. Plain functions, no browser APIs, so they run in the content script,
// service worker, popup and Node tests.

function matchesDomain(host, domains) {
  if (!host) return false;
  return domains.some((d) => host === d || host.endsWith("." + d));
}

// Rough "site" (registrable domain) used to tell first-party from third-party hosts.
// Heuristic, not the full Public Suffix List. Handles common patterns like co.in / co.uk.
function siteOf(host) {
  if (!host) return "";
  host = host.toLowerCase();
  if (/^\d+(\.\d+){3}$/.test(host) || host.includes(":")) return host; // IP address
  const p = host.split(".");
  if (p.length <= 2) return host;
  const secondLevel = ["co", "com", "org", "net", "ac", "gov", "edu", "nic", "res"];
  const last = p[p.length - 1];
  const second = p[p.length - 2];
  if (last.length === 2 && secondLevel.includes(second)) return p.slice(-3).join(".");
  return p.slice(-2).join(".");
}

function isThirdParty(host, pageHost) {
  return siteOf(host) !== siteOf(pageHost);
}

function parseVersion(v) {
  return String(v).split(".").map((n) => parseInt(n, 10) || 0);
}

function compareVersions(a, b) {
  const x = parseVersion(a);
  const y = parseVersion(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] || 0) - (y[i] || 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

// A version is vulnerable if it is below the fixed version of its own major branch,
// or below the lowest major branch we know a fix for.
function isVulnerableVersion(version, fixedIn) {
  const major = parseVersion(version)[0];
  const majors = fixedIn.map((f) => parseVersion(f)[0]);
  if (major < Math.min(...majors)) return true;
  const fixed = fixedIn.find((f) => parseVersion(f)[0] === major);
  return fixed ? compareVersions(version, fixed) < 0 : false;
}

/**
 * Find known libraries and their versions from script URLs (query strings are not used).
 * @returns {Array<{name, version, vulnerable, eol, severity, note, url}>}
 */
function detectLibraries(urls, libRules) {
  const found = [];
  const seen = new Set();
  for (const url of urls) {
    for (const lib of libRules) {
      const m = new RegExp(lib.pattern, "i").exec(url);
      if (!m) continue;
      const version = m[1];
      const key = lib.name + "@" + version;
      if (seen.has(key)) continue;
      seen.add(key);
      const eol = !!lib.eol;
      const vulnerable = lib.fixedIn ? isVulnerableVersion(version, lib.fixedIn) : false;
      if (eol || vulnerable) {
        found.push({ name: lib.name, version, vulnerable, eol, severity: lib.severity || "medium", note: lib.note || "", url });
      }
    }
  }
  return found;
}

if (typeof module !== "undefined") {
  module.exports = { matchesDomain, siteOf, isThirdParty, parseVersion, compareVersions, isVulnerableVersion, detectLibraries };
}
