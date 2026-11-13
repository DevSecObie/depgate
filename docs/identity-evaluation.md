# Build-identity checks: evaluation

Measured 2026-11-13. Re-run with `scripts/measure_identity.py` (live PyPI) and
`python -m unittest discover -s tests` (incident replays, offline).

Two checks are measured here:

- **build-identity**: a signed release built somewhere other than the package's
  earlier signed releases (ref, trigger, workflow, signer, runner, environment,
  repository and owner IDs).
- **attestation-dropped**: an unsigned release after signed ones in the same
  release line (up to 3 unsigned in a row; after that the project is taken to
  have stopped signing).

## Real incidents (real signing certificates, in `tests/fixtures/incidents/`)

| Incident | What happened | depgate |
|---|---|---|
| Red Hat npm, June 2026 (`@redhat-cloud-services/types@3.6.1`) | Copy of `ci.yaml` pushed to a throwaway branch; valid attestation | **Flagged** (build-identity). Only the ref differs: `refs/heads/oidc-61fff775` vs `refs/heads/master` for the five releases before it. |
| axios npm, March 2026 (`axios@1.14.1`) | Hijacked maintainer account published by hand, no provenance | **Flagged** (attestation-dropped). The four releases before it were signed by `axios/axios` `publish.yml`. |
| Ultralytics PyPI, Dec 2024, second round (8.3.45, 8.3.46) | Published with a leftover API token, no attestations | **Flagged** (attestation-dropped), same shape as axios. Replayed with a synthetic unsigned release on real signed history. |
| Ultralytics PyPI, Dec 2024, first round (Sigstore entry 153589716) | GitHub Actions cache poisoning inside the real release workflow | **Not caught.** Same repo, workflow, ref (`main`), trigger (`push`), and the signed commit is the real `8.3.42` version-bump commit. |
| Ultralytics 8.3.43 (legitimate clean-up release) | Released by hand from a personal branch | **Flagged (false positive)**: ref and trigger changed. |

The Red Hat malicious certificate comes from the Sigstore transparency log,
since npm removed the release. axios 1.14.1's missing provenance is from public
write-ups (Trend Micro, Snyk, Endor Labs); its legitimate predecessors' certificates
are real.

## False-positive rate on popular PyPI packages

Top 200 PyPI packages by downloads (30 days), last 12 releases each. Every
release with signed history is compared with up to 5 signed releases before it.

| | |
|---|---|
| Packages with attestations | 108 of 200 |
| Releases compared | 947 |
| Releases flagged | 29 (3.06%), in 19 packages |
| ...by build-identity | 17 |
| ...by attestation-dropped | 12 |
| Releases blocked | 0 |

All 29 looked legitimate on inspection:

- Release-process changes: pluggy moved to `deploy.yml`; matplotlib and
  scikit-learn moved builds to separate `*-release` repos.
- Repository transfer: propcache to aio-libs (new owner ID, same repository).
- Manual or one-off releases (`workflow_dispatch`): aiobotocore, rpds-py,
  sqlalchemy; hf-xet dev releases from personal branches.
- Switching between tag and branch releases: oauthlib, threadpoolctl.
- Projects that stopped signing: annotated-doc, httpx2, httpcore2, watchfiles,
  sse-starlette, google-cloud-bigquery. Their first three unsigned releases
  are flagged; later ones are info.

These are the changes a person should glance at, which is why both checks
default to "flag" (ask), not "block".

Tuning that got here:

- Treating version numbers in branch names as a pattern (`release-9.2.0` ≈
  `release-9.1.1`) cut a 30-package trial from 10.2% to 2.2%.
- Judging drops within the release line, and treating a long unsigned run as
  "stopped signing", cut attestation-dropped from 29 flags to 6 when only the
  first unsigned release was flagged. Code review then showed an attacker could
  publish a harmless unsigned release first and the malicious one second, so
  up to 3 unsigned releases in a row are flagged now: 12 flags. That trade
  costs 0.6 points of flag rate.

npm has no public top-packages list, so it has no false-positive measurement yet.

## Limits

- Attacks inside the real release pipeline (cache poisoning, a compromised
  dependency of the build) keep the normal identity and the real commit. Not caught.
- Someone who can push a branch matching the project's release-branch pattern,
  or a tag, can blend in. The ref is still shown in the output.
- An attacker who first publishes 3 or more unsigned releases gets the later
  ones reported as info ("stopped signing").
- A package with one earlier signed release has a thin baseline; one legitimate
  oddity there produces a flag (packaging 26.0rc2).
- Earlier releases' identities come from the registry's stored attestations (PyPI
  verified them at upload); depgate re-verifies only the release being checked.
- `npm install` / `pnpm install` with no package names installs from the
  lockfile; the hook has nothing to check there.
