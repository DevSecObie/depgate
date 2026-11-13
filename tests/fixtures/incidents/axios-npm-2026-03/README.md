# axios npm compromise (March 2026): real signing certificates

Package: `axios`. Each `.cert.b64` is the base64 DER Fulcio certificate from that
version's SLSA provenance, from npm's attestations API, fetched 2026-11-13.

- `1.13.2`, `1.13.5`, `1.13.6`, `1.14.0`: legitimate releases, signed by
  `axios/axios` `publish.yml` in GitHub Actions.
- `1.14.1` (malicious, published 2026-03-31 00:21 UTC, since removed): published
  by hand from a hijacked maintainer account with **no provenance attestation**.
  Sources: https://www.trendmicro.com/en/research/26/c/axios-npm-package-compromised.html,
  https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/,
  https://endorlabs.com/learn/npm-axios-compromise

depgate's `attestation-dropped` check flags a release without an attestation
when earlier releases were signed.
