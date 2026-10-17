# Scoring methodology

The score is an **indicative heuristic** built from passive checks. It is not a PCI DSS compliance
determination, a penetration test, or an official MITRE rating. MITRE ATT&CK is used to *explain*
what each weakness enables; it does not compute the number. All weights live in
`rules/posture.json` so they are open to review and tuning.

## Formula

```
score = clamp( baseline(integration type) - provider penalties - client penalties , 0, 100 )
```

| Integration type | Baseline | Why |
|---|---|---|
| hosted | 92 | Card data never touches the merchant site |
| api-hosted | 82 | Gateway fields/SDK on a merchant-controlled page |
| off-website | 60 | Payment happens elsewhere, so this page is largely unverifiable |
| self-hosted | 55 | Card data handled by the merchant, largest PCI scope |

Severity points: critical 30, high 18, medium 10, low 4, info 0.
Provider penalties are capped at 55 and client penalties at 20, so one category can't zero the score
on its own. Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F below.

If the classification confidence is low, the score is shown as provisional.

## Findings and mappings

| Finding | Severity | ATT&CK | PCI DSS v4.0 |
|---|---|---|---|
| Plain HTTP page | critical | T1557, T1040 | 4.2.1 |
| Card form posts over HTTP | critical | T1557, T1040 | 4.2.1 |
| Mixed content | high | T1557 | 4.2.1 |
| No HSTS | medium | T1557 | 4.2.1 |
| No CSP (high on payment pages) | medium/high | T1059.007, T1189, T1056 | 6.4.3, 11.6.1 |
| Weak CSP | medium | T1059.007, T1189 | 6.4.3 |
| Card form posts to unknown domain | high | T1041, T1056 | 6.4.3 |
| Many third-party script hosts | medium/high | T1195, T1056, T1059.007 | 6.4.3 |
| Third-party scripts without SRI | low/medium | T1195 | 6.4.3 |
| Outdated or end-of-life JS library | low/medium | T1189, T1059.007 | 6.3.3 |
| No framing protection | low/medium | none (CWE-1021) | none |
| Server version disclosure | low | T1592.002 | none |
| Old browser (client) | medium/high | T1189, T1203 | none |
| Unsupported OS (client) | medium/high | T1189, T1203 | none |

Third-party thresholds are halved on payment pages. Gateway SDKs are excluded from the
third-party and SRI findings because they must be loaded live from the gateway.

## What it cannot see

- **Server OS and service versions.** A passive browser extension can't learn these. It sees only what
  the server volunteers (headers) and what the page loads. Actively probing a server you don't own is
  out of scope on purpose.
- **TLS version and certificate details.** Chrome extensions can't read them.
- **Fields inside cross-origin iframes**, server-side code, and backend payment flows.
- **Mobile apps.** Chrome for Android and iOS Safari don't run this extension. App analysis
  (APK/IPA) is a separate planned module.

## Keeping it honest

- Browser and OS baselines have a review date. After 120 days the version checks switch off and the
  popup says so, instead of guessing.
- Library fingerprints only read versions that appear in script URLs.
- Add a test for every new rule.
