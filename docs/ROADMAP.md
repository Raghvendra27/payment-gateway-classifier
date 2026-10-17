# Roadmap

- [x] v0.1: classify hosted / API-hosted / self-hosted / off-website (UPI links)
- [x] v0.2: passive provider posture checks, client posture checks, transparent scoring,
      ATT&CK and PCI DSS mapping, JSON report export
- [ ] v0.3: redirect-chain evidence for hosted checkouts, local bank / netbanking / 3-D Secure detection
- [ ] v0.4: optional backend for TLS/certificate checks and NVD/CISA KEV lookups
- [ ] v0.5: Firefox build
- [ ] v1.0: separate APK/IPA analyzer for mobile apps (gateway SDKs, cleartext traffic, min SDK)

## Design rules
- Passive only. No active probing of third-party servers.
- Least privilege permissions.
- Rules live in `rules/*.json` so they can be updated without code changes.
- The score is a documented, custom formula. ATT&CK explains risk, it doesn't calculate it.
