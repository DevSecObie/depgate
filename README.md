# depgate

A dependency admission gate for PyPI. Give it a package, a requirements file, or a shell command, and it answers **allow**, **flag**, or **block**, with the reasons.

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

## Gating an AI coding agent (Claude Code hook)

`depgate --hook` runs as a Claude Code `PreToolUse` hook. When the agent tries to run a Bash command that installs packages (`pip`, `python -m pip`, `uv add`, `uv pip install`, `poetry add`, `pipx install`), depgate evaluates every package with the agent profile first:

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

- PyPI only.
- Version ranges like `flask>=3.0` are checked against the latest release, not resolved. Pin versions for accurate results.
- Transitive dependencies aren't evaluated; only the packages named directly.
- Publisher consistency is checked for GitHub publishers only.
- Does not inspect package contents.

## Tests

```bash
python -m unittest discover -s tests
```

The tests use a fake PyPI and a stand-in verifier, so they need no network access.
