# Payment Gateway Classifier

A browser extension that passively detects **what kind of payment gateway integration** a page uses,
then gives a transparent **security score** based on the integration type, the page's observable
security posture, and the visitor's own browser and OS. Findings are mapped to **MITRE ATT&CK**
techniques and **PCI DSS v4.0** requirements.

## What you see

Click the extension icon on a checkout page:

- **Class and gateway**: `hosted`, `api-hosted`, `self-hosted`, `off-website` (or `none`)
- **Score and grade** with a breakdown (baseline, provider, client)
- **Findings** with severity, fix advice, ATT&CK technique IDs, PCI references
- **This device**: browser and OS as the page can see them
- **Copy report (JSON)** for sharing or logging

| Class | Meaning |
|---|---|
| `hosted` | You are on the gateway's own page (redirect checkout) |
| `api-hosted` | Merchant page embeds the gateway's iframe or SDK |
| `self-hosted` | Card fields live on the merchant's own page, no known gateway components |
| `off-website` | Payment happens outside the page (e.g. UPI deep links) |

## Install (development)

1. Clone or download this repo.
2. Open `chrome://extensions` and enable **Developer mode**.
3. Click **Load unpacked** and select the repo folder (the one containing `manifest.json`).
4. Open a checkout page and click the extension icon. After updating the extension, reload the page.

Works in Chrome and other Chromium browsers (Edge, Brave). Firefox is on the roadmap.

## Permissions (and why)

- `webRequest` + site access: read **response headers** of the page you are on (HSTS, CSP, framing).
  Headers are observed, never modified or blocked.
- `activeTab`, `storage`: show results for the current tab; keep them in session storage only.
- Nothing is sent anywhere. There is no server and no analytics.

## How it works

- `src/content.js`: passive page signals (iframe/script origins, card field presence, card form targets,
  mixed content). Never reads field values; query strings are stripped from URLs.
- `src/classifier.js`: matches signals against `rules/gateways.json`.
- `src/analyzer.js`: runs checks and computes the score using `rules/posture.json`.
- `src/background.js`: stores the classification and captured headers per tab.
- `popup/`: renders everything.

Scoring details and the full finding table: [docs/SCORING.md](docs/SCORING.md).

## Tests

```bash
npm test
```

Node 18+, no dependencies. CI runs the same command on every push.

## Limitations

- It can't see server OS or service versions, TLS details, or fields inside cross-origin iframes.
- Mobile apps need a separate analyzer (roadmap). Chrome for Android doesn't run extensions.
- Gateway fingerprints and library rules are a starter set and need verification and growth.
- Browser/OS baselines expire after 120 days and then switch themselves off.
- The score is indicative, not a compliance verdict.

## Ethics

Passive observation of pages you visit. No scanning or probing of third-party servers.

## Contributing

Add or correct fingerprints in `rules/gateways.json`, adjust weights in `rules/posture.json`,
and add a test in `tests/` for every rule change.

## License

MIT
