// Collects passive signals from the page and sends them to the background worker.
// It never modifies the page, never reads field values, and strips query strings from URLs.
(function () {
  const CARD_SELECTOR = [
    'input[autocomplete="cc-number"]',
    'input[name*="card" i][name*="number" i]',
    'input[id*="card" i][id*="number" i]'
  ].join(",");

  function parse(url) {
    try { return new URL(url, location.href); } catch (e) { return null; }
  }
  function uniqueHosts(selector, attr) {
    const set = new Set();
    document.querySelectorAll(selector).forEach((el) => {
      const u = parse(el.getAttribute(attr));
      if (u) set.add(u.hostname);
    });
    return [...set];
  }

  function collect() {
    const scriptItems = [];
    document.querySelectorAll("script[src]").forEach((el) => {
      const u = parse(el.getAttribute("src"));
      if (u && scriptItems.length < 200) {
        scriptItems.push({ url: u.origin + u.pathname, host: u.hostname, sri: el.hasAttribute("integrity") });
      }
    });

    const cardForms = [];
    document.querySelectorAll("form").forEach((f) => {
      if (!f.querySelector(CARD_SELECTOR)) return;
      const a = parse(f.getAttribute("action") || "");
      if (a) cardForms.push({ scheme: a.protocol, host: a.hostname });
    });

    const mixedCount = location.protocol === "https:"
      ? document.querySelectorAll('script[src^="http:"], iframe[src^="http:"], img[src^="http:"], link[rel="stylesheet"][href^="http:"]').length
      : 0;

    return {
      pageScheme: location.protocol,
      iframeHosts: uniqueHosts("iframe[src]", "src"),
      scriptHosts: uniqueHosts("script[src]", "src"),
      scriptItems,
      cardFieldOnPage: !!document.querySelector(CARD_SELECTOR),
      cardForms,
      mixedCount,
      upiLinks: document.querySelectorAll('a[href^="upi://"]').length
    };
  }

  let timer = null;
  function report() {
    chrome.runtime.sendMessage({
      type: "signals",
      host: location.hostname,
      pageUrl: location.origin + location.pathname,
      signals: collect()
    });
  }
  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(report, 800); // checkout widgets often load late
  }

  report();
  new MutationObserver(schedule).observe(document.documentElement, { childList: true, subtree: true });
})();
