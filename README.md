# depgate

A dependency admission gate for PyPI, with build-identity checks for npm. Give it a package, a requirements file, or a shell command, and it answers **allow**, **flag**, or **block**, with the reasons.

It's built for AI-assisted development. Coding agents sometimes recommend packages that don't exist, and attackers register those hallucinated names with malicious code ("slopsquatting"). A human picking a package and an agent picking one carry different risk, so depgate has a stricter profile for agents, and a hook that stops an agent's `pip install` before it runs.

The core needs only the Python standard library (3.11+). A supply-chain tool shouldn't widen your own supply chain. Signature verification is an optional extra.

## Quick start

```bash
pip install -e .            # core checks
pip install -e '.[verify]'  # adds cryptographic attestation verification

depgate requests                      # check the latest version
depgate requests==2.32.3              # check a specific version
depgate --agent some-package          # stricter policy for agent-proposed packages
depgate -r requirements.txt --json    # a whole file, machine-readable for CI
depgate --cmd "pip install foo bar"   # what would this command install?
```

Example:

```
BLOCK  reqeusts  [agent]
  X exists: 'reqeusts' does not exist on PyPI. An AI agent proposed a package
    that does not exist (possible hallucination). Did you mean: requests?

BLOCK  urllib3==1.26.4  [agent]
  X vulnerabilities: 11 known vulnerabilities: CVE-2021-33503 (fixed in 1.26.5),
    CVE-2024-37891 (fixed in 1.26.19, 2.2.2), ... and 6 more.

ALLOW  flask==3.1.3  [default]
  - provenance: Signatures verified: built by GitHub:pallets/flask.
```

## Build identity: was this release built where the last ones were?

Trusted Publishing pins a repository and workflow file, but not the branch. In the Red Hat npm compromise (June 2026) an attacker pushed a copy of the release workflow to a throwaway branch and published a release whose attestation verified. Checking that an attestation exists, or that it verifies, doesn't catch that.

Each attestation's Sigstore certificate records the full build identity: git ref, trigger event, workflow, signing workflow, runner type, deployment environment, repository visibility, and the repository's and owner's permanent numeric IDs. depgate reads it and compares it with the package's own last 5 signed releases:

```
FLAG   rhtypes==3.6.1  [default]
  - provenance: Signatures verified: built by GitHub:RedHatInsights/frontend-components.
  ! build-identity: Built from refs/heads/oidc-61fff775, unlike earlier releases (refs/heads/master).
    Compared with 3.6.0, 3.5.2, 3.5.1, 3.5.0, 3.4.2. Build run: https://github.com/RedHatInsights/...
```

(That's the real certificate from the Red Hat attack, replayed in the tests.)

| Change | Default |
|---|---|
| Same repository name, new numeric repository ID (deleted and re-created) | block |
| Different repository or owner | flag |
| New ref family, trigger, workflow, signing workflow, runner type, environment, visibility | flag |
| Repository renamed or transferred (same numeric ID) | info |

Version numbers in branch names are treated as a pattern, so `release-9.2.0` matches `release-9.1.1`. Tags match tags.

**Signatures that stop.** A release with no attestation, after signed releases in the same release line, is flagged (`attestation-dropped`). That's how the axios compromise (March 2026, hijacked account) and the second round of the Ultralytics compromise (December 2024, leftover API token) looked. Up to three unsigned releases in a row are flagged; after that the project is taken to have stopped signing, and a release line that was never signed is reported as info.

How often these fire on legitimate releases: 3.06% of 947 recent releases across the top 200 PyPI packages, none blocked. Each one was a real change worth a glance (a new release workflow, a repo transfer, a manual release, a project that stopped signing). They do **not** catch attacks inside the real pipeline, like the Ultralytics cache poisoning. Details: [docs/identity-evaluation.md](docs/identity-evaluation.md).

**npm.** `depgate npm:<name>[@version|range|tag]` runs the build-identity and attestation-dropped checks on npm packages, and the hook checks `npm install`, `pnpm add`, `yarn add` and `bun add` the same way. depgate doesn't repeat for npm what other tools already cover (malware, typosquats, cooldowns). Ranges (`^`, `~`, `1.x`, `>=`) and dist-tags are resolved to the version npm would install; ranges depgate can't resolve are flagged rather than guessed. With the `verify` extra, the provenance bundle's Sigstore signature is verified and its sha512 must match the tarball. Aliases (`foo@npm:bar`), git and file specs, and registries set by option, environment variable or config file are flagged as bypassing registry checks.

```bash
depgate npm:@redhat-cloud-services/types npm:axios@1.21.1
```

**Run beside other tools.** `--identity-only` skips the checks other tools already do (typosquats, age, vulnerabilities), so depgate adds one signal without repeating alerts:

```bash
depgate --identity-only -r requirements.txt
```

**Pin identities.** Record each package's expected build identity next to your lockfile and commit it. Later checks compare with the pin as well as with recent history:

```bash
depgate -r requirements.txt --pins depgate-pins.json --update-pins   # record
depgate -r requirements.txt --pins depgate-pins.json                 # compare
```

**PEP 751.** `--pep751` prints each package's Trusted Publisher identity as `pylock.toml` `attestation-identities` entries, for installers that enforce them. That record is coarser than a pin (no ref, trigger or repository ID).

## Gating an AI coding agent (Claude Code hook)

`depgate --hook` runs as a Claude Code `PreToolUse` hook. When the agent tries to run a Bash command that installs packages (`pip`, `python -m pip`, `uv add`, `uv pip install`, `poetry add`, `pipx install`, and for npm packages `npm install`, `pnpm add`, `yarn add`, `bun add`), depgate evaluates every package with the agent profile first:

| Verdict | What happens |
|---|---|
| block | The command is denied, and depgate's reasons go back to the agent |
| flag | You're asked to approve it, with the reasons shown |
| allow | depgate stays silent; your normal permission rules apply |

depgate never auto-approves a command. "Allow" only means it adds no objection. If depgate itself errors (network down, etc.), it asks you instead of letting the install through.

Add to `.claude/settings.json` (project) or `~/.claude/settings.json` (user):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "depgate --hook" }]
      }
    ]
  }
}
```

The command parser handles chained commands (`cd app && pip install x`), `sudo`, versioned interpreters (`python3.12 -m pip`), and option values that aren't packages (`--target dir`). Installs that bypass PyPI checks entirely, such as a custom `--index-url`, a `git+https://` URL, or a local path, are flagged rather than silently allowed.

## Exit codes

| Code | Verdict | Meaning |
|---|---|---|
| 0 | allow | Nothing concerning found |
| 1 | flag | A person should look before it goes in |
| 2 | block | Do not admit |

With several packages, the exit code is the worst verdict. In CI, fail on `2` and require review on `1`. (In `--hook` mode the decision goes in the JSON output and the exit code is always 0.)

## What it checks

| Check | What it looks at | Default | Agent |
|---|---|---|---|
| `exists` | Package exists on PyPI. Suggests the real name if it looks like a typo. | block | block |
| `version` | Requested version exists, has files, and isn't yanked. | block | block |
| `typosquat` | Name is within edit distance of a popular package, or adds/drops common affixes (`-python`, `py-`, `2`). | flag (distance 1) | block (distance 2) |
| `project-age` | When the project was first published. | flag under 90 days | block under 30, flag under 180 |
| `release-age` | When this specific version was published (a cooldown for fresh releases). | flag under 3 days | flag under 7 days |
| `history` | Number of releases. | flag under 3 | flag under 5 |
| `install-code` | No wheel, so `pip install` builds from source and runs the package's own build code. | flag | flag |
| `vulnerabilities` | Known, non-withdrawn vulnerabilities in this version (PyPI's data, sourced from OSV). Duplicate advisories for the same CVE count once. | flag | block |
| `provenance` | PEP 740 attestations from Trusted Publishing, cryptographically verified (see below). | missing: info; **invalid: block** | missing: flag, unless established; **invalid: block** |
| `publisher-mismatch` | The verified builder repo vs. the source repo the project advertises. | flag if different owner | flag if different owner |
| `metadata` | Project lists a source repository or homepage. | info | flag |
| `build-identity` | Where this release was built (ref, trigger, workflow, runner, environment, repository ID) vs. the package's last signed releases. See above. | flag (block if repo re-created) | flag (block if repo re-created) |
| `identity-pin` | Same comparison against a pins file (`--pins`). | flag | flag |
| `attestation-dropped` | No attestation on this release, but earlier releases in its line were signed. | flag | flag |

"Established" means at least 730 days old **and** at least 10 releases. Most long-standing packages predate PyPI attestations, so a missing attestation on an established project is reported but not counted against it.

## Provenance verification

With the `verify` extra installed, depgate doesn't just check that attestations exist. For every file in the release it confirms:

1. The Sigstore signature on the attestation is valid.
2. The signing certificate was issued to the Trusted Publisher PyPI recorded (for example, a specific GitHub repository and workflow).
3. The attested digest matches the sha256 PyPI reports for that file.

Any failure blocks the package, since a forged or mismatched attestation is a stronger signal than no attestation. If Sigstore's trust-root update service is unreachable, depgate falls back to the trust root bundled with the library and says so in the output.

**Publisher consistency.** A valid signature proves which repository built the file, but not that it's the repository you think you're getting. depgate compares the verified builder against the GitHub repo in the project's metadata:

- Same repo: nothing to report.
- Same owner, different repo: noted, not flagged. Some projects build releases from a dedicated repo (numpy publishes from `numpy/numpy-release`).
- Different owner: flagged. The release was built somewhere other than where the project says its code lives.

## Tuning

Copy `depgate.example.toml`, change what you need, and pass it with `--policy`. Each table overrides one profile; anything you leave out keeps its built-in value. Unknown keys are rejected so typos in the policy file don't fail silently.

```bash
depgate --policy depgate.toml --agent -r requirements.txt
depgate --hook --policy ~/.config/depgate.toml   # hooks can use a policy too
```

The typosquat check compares against a built-in snapshot of popular packages. For production, point `popular_file` at a fresh list (one name per line).

## Limitations

- PyPI for all checks; npm for build identity and attestation-dropped only.
- A bare `npm install` (from the lockfile) names no packages, so the hook has nothing to check.
- Version ranges like `flask>=3.0` are checked against the latest release, not resolved. Pin versions for accurate results.
- Transitive dependencies aren't evaluated; only the packages named directly.
- Publisher consistency is checked for GitHub publishers only.
- Does not inspect package contents.
- Build identity can't see attacks inside the real release pipeline (cache poisoning, a compromised build dependency).

## Tests

```bash
python -m unittest discover -s tests
```

The tests use a fake PyPI and a stand-in verifier, so they need no network access. Incident replays use real signing certificates saved in `tests/fixtures/incidents/`.

To measure how often build-identity checks fire on real releases (needs network):

```bash
python scripts/measure_identity.py --top 200 --releases 12
```
