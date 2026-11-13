# Ultralytics PyPI compromise (December 2024): real signing certificates

Package: `ultralytics`. Each `.cert.b64` is a base64 DER Fulcio certificate.

- `8.3.38`, `8.3.39`, `8.3.40`: legitimate releases before the attack, from
  PyPI's Integrity API, fetched 2026-11-13. Built from `refs/heads/main` on `push`.
- `rekor-153589716`: the Sigstore log entry linked from PyPI's incident analysis
  (https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/,
  https://search.sigstore.dev/?logIndex=153589716), signed 2024-12-05 12:47 UTC.
  The article doesn't say which malicious version it belongs to, but says the
  first malicious releases were published "through the existing GitHub Actions
  workflow". Its identity matches the legitimate releases exactly.
- `8.3.43`: the legitimate clean-up release after the attack. Built from
  `refs/heads/glenn-jocher-patch-1` on `workflow_dispatch`.

What this shows:
- Cache poisoning inside the real release pipeline is invisible to identity
  checks (same repo, workflow, ref and trigger). depgate does not catch it.
- Legitimate releases sometimes come from an unusual ref and trigger (8.3.43);
  depgate flags these. That is a known false positive, and why identity
  changes are "flag" (ask a person), not "block".
