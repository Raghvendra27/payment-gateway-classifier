// Security analysis and scoring. Pure functions: everything comes in as arguments,
// so the same code runs in the popup and in Node tests.
//
// Score = clamp(baseline(gateway class) - provider penalties - client penalties, 0, 100)
// See docs/SCORING.md for the full methodology.

const _aU = typeof module !== "undefined" ? require("./util.js") : globalThis;

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

function bump(sev) {
  const i = SEV_ORDER.indexOf(sev);
  return i > 0 ? SEV_ORDER[i - 1] : sev;
}

// ---------- Content-Security-Policy ----------

function parseCsp(value) {
  return String(value || "")
    .split(",")
    .map((policy) => {
      const d = {};
      policy.split(";").forEach((part) => {
        const t = part.trim().split(/\s+/).filter(Boolean);
        if (t.length) d[t[0].toLowerCase()] = t.slice(1).map((x) => x.toLowerCase());
      });
      return d;
    })
    .filter((p) => Object.keys(p).length > 0);
}

function cspAssessment(value) {
  const policies = parseCsp(value);
  if (!policies.length) return { present: false, weak: false, frameAncestors: false };
  const weakOne = (p) => {
    const src = p["script-src"] || p["default-src"];
    if (!src) return true; // does not restrict scripts at all
    if (src.includes("*")) return true;
    const hasNonceOrHash = src.some((t) => /^'(nonce-|sha(256|384|512)-)/.test(t));
    const strict = src.includes("'strict-dynamic'");
    return src.includes("'unsafe-inline'") && !hasNonceOrHash && !strict;
  };
  return {
    present: true,
    weak: policies.every(weakOne),
    frameAncestors: policies.some((p) => "frame-ancestors" in p),
  };
}

// ---------- Client info ----------

/**
 * @param {object|null} hi  navigator.userAgentData.getHighEntropyValues() result (or low-entropy data)
 * @param {string} ua       navigator.userAgent (fallback)
 */
function parseClient(hi, ua) {
  const c = { source: null, browser: null, chromiumMajor: null, os: null, osVersion: null, osMajor: null, mobile: false };
  const major = (v) => parseInt(String(v).split(".")[0], 10);

  if (hi && hi.platform) {
    c.source = "uaData";
    c.os = hi.platform;
    c.mobile = !!hi.mobile;
    const list = hi.fullVersionList && hi.fullVersionList.length ? hi.fullVersionList : hi.brands || [];
    const pick = (n) => list.find((b) => b.brand === n);
    const chromium = pick("Chromium");
    const named = pick("Microsoft Edge") || pick("Google Chrome") || pick("Opera");
    c.browser = named ? named.brand : chromium ? "Chromium-based browser" : null;
    const v = chromium || named;
    if (v) c.chromiumMajor = major(v.version);
    if (hi.platformVersion) {
      c.osVersion = hi.platformVersion;
      c.osMajor = major(hi.platformVersion);
    }
    return c;
  }

  if (ua) {
    // Chrome freezes parts of the UA string, so only the browser major is trusted here.
    c.source = "ua";
    c.mobile = /Mobile|Android/i.test(ua);
    let m;
    if ((m = /Edg\/(\d+)/.exec(ua))) { c.browser = "Microsoft Edge"; c.chromiumMajor = parseInt(m[1], 10); }
    else if ((m = /Chrome\/(\d+)/.exec(ua))) { c.browser = "Google Chrome"; c.chromiumMajor = parseInt(m[1], 10); }
    else if (/Firefox\//.test(ua)) { c.browser = "Firefox"; }
    else if (/Safari\//.test(ua)) { c.browser = "Safari"; }
    if (/Windows/.test(ua)) c.os = "Windows";
    else if (/Android/.test(ua)) c.os = "Android";
    else if (/Mac OS X/.test(ua)) c.os = "macOS";
    else if (/Linux/.test(ua)) c.os = "Linux";
    return c;
  }
  return c;
}

// ---------- Analysis ----------

/**
 * @param {object} input
 *   rules          parsed rules/posture.json
 *   gateways       parsed rules/gateways.json
 *   classification { class, gateway, confidence, host }
 *   signals        content-script signals
 *   headers        response headers of the top-level page (lowercase keys) or null
 *   client         result of parseClient()
 *   now            ms timestamp (for rule staleness)
 */
function analyze(input) {
  const { rules, gateways, classification, headers, client } = input;
  const signals = input.signals || {};
  const now = input.now || Date.now();
  const cls = classification.class;

  const base = {
    class: cls,
    gateway: classification.gateway || null,
    confidence: classification.confidence,
  };
  if (cls === "none") {
    return { ...base, applicable: false, score: null, grade: null, findings: [], techniques: [] };
  }

  const pageHost = classification.host || "";
  const paymentPage = rules.paymentPageClasses.includes(cls);
  const findings = [];
  const add = (id, title, severity, category, detail, extra = {}) =>
    findings.push({ id, title, severity, category, detail, fix: extra.fix || "", attack: extra.attack || [], pci: extra.pci || [], cwe: extra.cwe || [] });

  const gwDomains = [];
  gateways.gateways.forEach((g) => gwDomains.push(...g.scriptDomains, ...g.frameDomains, ...g.hostedDomains));
  const isGatewayHost = (h) => _aU.matchesDomain(h, gwDomains);

  // Gateway context (informational, explains the baseline)
  add("gw-context", "Integration type: " + cls, "info", "gateway", rules.saq[cls] || "", {});

  // ----- Provider posture -----
  const https = signals.pageScheme === "https:";
  if (signals.pageScheme === "http:") {
    add("tls-none", "Page is served over plain HTTP", "critical", "provider",
      "Anything the user types or receives on this page can be read or changed on the network.",
      { fix: "Serve the whole site over HTTPS and redirect HTTP to HTTPS.", attack: ["T1557", "T1040"], pci: ["PCI DSS v4.0 req 4.2.1"] });
  }

  if (https) {
    if (!headers) {
      add("meta-no-headers", "Response headers not captured", "info", "meta",
        "Reload the page with the extension enabled to include header checks (HSTS, CSP, framing).", {});
    } else {
      if (!headers["strict-transport-security"]) {
        add("hsts-missing", "No HSTS header", "medium", "provider",
          "Without Strict-Transport-Security, a first visit over HTTP can be downgraded or intercepted.",
          { fix: "Send Strict-Transport-Security with a long max-age.", attack: ["T1557"], pci: ["PCI DSS v4.0 req 4.2.1"] });
      }

      const csp = cspAssessment(headers["content-security-policy"]);
      if (!csp.present) {
        add("csp-missing", "No Content-Security-Policy", paymentPage ? "high" : "medium", "provider",
          "Nothing limits which scripts can run on this page, so an injected or compromised script can read card fields (web skimming).",
          { fix: "Add a CSP that restricts script-src to known origins, using nonces or hashes.", attack: ["T1059.007", "T1189", "T1056"], pci: ["PCI DSS v4.0 req 6.4.3", "PCI DSS v4.0 req 11.6.1"] });
      } else if (csp.weak) {
        add("csp-weak", "Content-Security-Policy does not effectively restrict scripts", "medium", "provider",
          "The policy allows inline scripts without nonces or hashes, uses a wildcard, or leaves scripts unrestricted.",
          { fix: "Remove 'unsafe-inline' and wildcards from script-src; use nonces or hashes.", attack: ["T1059.007", "T1189"], pci: ["PCI DSS v4.0 req 6.4.3"] });
      }

      const framed = !!headers["x-frame-options"] || (csp.present && csp.frameAncestors);
      if (!framed) {
        add("frame-missing", "Page can be embedded in other sites (no clickjacking protection)", paymentPage ? "medium" : "low", "provider",
          "Neither X-Frame-Options nor CSP frame-ancestors is set, so another site could overlay this page in a frame.",
          { fix: "Set CSP frame-ancestors 'self' (or X-Frame-Options: DENY/SAMEORIGIN).", cwe: ["CWE-1021"] });
      }

      const server = headers["server"] || "";
      const powered = headers["x-powered-by"] || "";
      if (/\d+\.\d+/.test(server) || powered) {
        add("version-disclosure", "Server software details are exposed", "low", "provider",
          "Headers reveal: " + [server && "Server: " + server, powered && "X-Powered-By: " + powered].filter(Boolean).join(", ") + ". This helps attackers pick known exploits.",
          { fix: "Remove or genericise Server and X-Powered-By headers.", attack: ["T1592.002"] });
      }
    }

    if (signals.mixedCount > 0) {
      add("mixed-content", "Page loads " + signals.mixedCount + " resource(s) over HTTP", "high", "provider",
        "Insecure resources on a secure page can be tampered with in transit.",
        { fix: "Load every resource over HTTPS.", attack: ["T1557"], pci: ["PCI DSS v4.0 req 4.2.1"] });
    }
  }

  // Card forms
  (signals.cardForms || []).forEach((f, i) => {
    if (https && f.scheme === "http:") {
      add("form-http-" + i, "Card form submits over plain HTTP", "critical", "provider",
        "The form on this HTTPS page posts card data to an insecure URL.",
        { fix: "Post card data only to HTTPS endpoints (or let the gateway collect it).", attack: ["T1557", "T1040"], pci: ["PCI DSS v4.0 req 4.2.1"] });
    }
    if (f.host && _aU.isThirdParty(f.host, pageHost) && !isGatewayHost(f.host)) {
      add("form-xdomain-" + i, "Card form submits to a different, unrecognised domain (" + f.host + ")", "high", "provider",
        "Card data leaves this site for a host that is not a known payment gateway.",
        { fix: "Confirm the destination is your gateway. Unknown destinations are a skimming indicator.", attack: ["T1041", "T1056"], pci: ["PCI DSS v4.0 req 6.4.3"] });
    }
  });

  // Third-party scripts
  const items = signals.scriptItems || [];
  const thirdHosts = new Set();
  const thirdNoSri = [];
  items.forEach((s) => {
    if (!_aU.isThirdParty(s.host, pageHost)) return;
    if (isGatewayHost(s.host)) return; // gateway SDKs are expected and cannot be pinned with SRI
    thirdHosts.add(s.host);
    if (!s.sri) thirdNoSri.push(s.host);
  });
  const tp = rules.thirdPartyScripts;
  const factor = paymentPage ? tp.paymentPageFactor : 1;
  const medAt = Math.ceil(tp.medium * factor);
  const highAt = Math.ceil(tp.high * factor);
  if (thirdHosts.size >= highAt) {
    add("third-party-many", thirdHosts.size + " third-party script hosts", "high", "provider",
      "Every extra script origin is code that can read the page. Hosts: " + [...thirdHosts].slice(0, 8).join(", ") + (thirdHosts.size > 8 ? ", ..." : ""),
      { fix: "Remove scripts you don't need on payment pages and justify the rest.", attack: ["T1195", "T1056", "T1059.007"], pci: ["PCI DSS v4.0 req 6.4.3"] });
  } else if (thirdHosts.size >= medAt) {
    add("third-party-some", thirdHosts.size + " third-party script hosts", "medium", "provider",
      "Hosts: " + [...thirdHosts].join(", "),
      { fix: "Keep scripts on payment pages to the minimum needed.", attack: ["T1195", "T1056"], pci: ["PCI DSS v4.0 req 6.4.3"] });
  }
  if (thirdNoSri.length > 0) {
    const sev = paymentPage && thirdNoSri.length >= rules.sriMediumCount ? "medium" : "low";
    add("sri-missing", thirdNoSri.length + " third-party script(s) without Subresource Integrity", sev, "provider",
      "Without an integrity hash, a changed third-party file runs unchecked. (Gateway SDKs are excluded because they must be loaded live.)",
      { fix: "Add integrity attributes to static third-party scripts, or self-host and pin them.", attack: ["T1195"], pci: ["PCI DSS v4.0 req 6.4.3"] });
  }

  // Outdated JS libraries
  const libs = _aU.detectLibraries(items.map((s) => s.url), rules.libraries);
  libs.forEach((l) => {
    add("lib-" + l.name.toLowerCase().replace(/[^a-z0-9]/g, ""), l.name + " " + l.version + (l.eol ? " (end of life)" : " (known vulnerabilities)"), l.severity, "provider",
      l.note, { fix: "Upgrade " + l.name + " to a maintained release.", attack: ["T1189", "T1059.007"], pci: ["PCI DSS v4.0 req 6.3.3"], cwe: ["CWE-1104"] });
  });

  // ----- Client posture -----
  const ageDays = (now - Date.parse(rules.reviewed)) / 86400000;
  const rulesFresh = ageDays <= rules.maxRuleAgeDays;
  const cr = rules.client;

  if (!client || !client.source) {
    add("meta-no-client", "Client details unavailable", "info", "meta", "This browser did not expose OS or browser version.", {});
  } else {
    if (!rulesFresh) {
      add("meta-stale-rules", "Version baselines are out of date", "info", "meta",
        "rules/posture.json was last reviewed " + rules.reviewed + ". Browser and OS version checks are skipped until it is updated.", {});
    } else {
      if (client.chromiumMajor) {
        const lag = cr.chromiumLatestKnown - client.chromiumMajor;
        if (lag >= cr.lagHigh) {
          add("client-browser-old", "Browser is far behind (" + client.browser + " " + client.chromiumMajor + ", latest known " + cr.chromiumLatestKnown + ")", "high", "client",
            "Old browser versions miss many security fixes, which raises the chance of drive-by exploitation.",
            { fix: "Update the browser.", attack: ["T1189", "T1203"] });
        } else if (lag >= cr.lagMedium) {
          add("client-browser-behind", "Browser is several releases behind (" + client.browser + " " + client.chromiumMajor + ", latest known " + cr.chromiumLatestKnown + ")", "medium", "client",
            "Security fixes ship in every release.", { fix: "Update the browser.", attack: ["T1189", "T1203"] });
        }
      }
      if (client.source === "uaData" && client.osMajor !== null && !isNaN(client.osMajor)) {
        if (client.os === "Windows") {
          if (client.osMajor === 0) {
            add("client-os-eol", "Windows 8.1 or older", "high", "client", "This Windows version no longer receives security updates.", { fix: "Upgrade the OS.", attack: ["T1189", "T1203"] });
          } else if (client.osMajor < 13) {
            add("client-os-win10", "Windows 10 is past standard end of support (14 Oct 2025)", "medium", "client",
              "Windows 10 only gets security updates through the paid Extended Security Updates program.", { fix: "Move to Windows 11 or enrol in ESU.", attack: ["T1203"] });
          }
        } else if (client.os === "macOS" && client.osMajor < cr.macMinMajor) {
          add("client-os-mac", "macOS " + client.osMajor + " is no longer supported", "medium", "client",
            "Apple typically patches only the latest three macOS versions.", { fix: "Upgrade macOS.", attack: ["T1203"] });
        } else if (client.os === "Android" && client.osMajor < cr.androidMinMajor) {
          add("client-os-android", "Android " + client.osMajor + " no longer receives security updates", "medium", "client",
            "Unpatched OS flaws weaken the device that handles the payment.", { fix: "Use a supported Android version.", attack: ["T1203"] });
        }
      }
    }
  }

  // ----- Score -----
  const pts = rules.severityPoints;
  const sum = (cat) => findings.filter((f) => f.category === cat).reduce((a, f) => a + pts[f.severity], 0);
  const providerPenalty = Math.min(sum("provider"), rules.caps.provider);
  const clientPenalty = Math.min(sum("client"), rules.caps.client);
  const baseline = rules.classBaseline[cls];
  const score = Math.max(0, Math.min(100, Math.round(baseline - providerPenalty - clientPenalty)));
  const grade = rules.grades.find((g) => score >= g.min).grade;

  findings.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));

  // ATT&CK roll-up
  const tech = {};
  findings.forEach((f) => {
    if (f.severity === "info") return;
    f.attack.forEach((id) => { (tech[id] = tech[id] || []).push(f.id); });
  });
  const techniques = Object.keys(tech).sort().map((id) => ({ id, name: rules.attackNames[id] || "", findings: tech[id] }));

  return {
    ...base,
    applicable: true,
    provisional: classification.confidence === "low",
    baseline, providerPenalty, clientPenalty, score, grade, findings, techniques,
  };
}

if (typeof module !== "undefined") module.exports = { analyze, parseClient, parseCsp, cspAssessment };
