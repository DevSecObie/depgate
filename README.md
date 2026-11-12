# depgate

A dependency admission gate for PyPI. Give it a package (or a requirements file) and it answers **allow**, **flag**, or **block**, with the reasons.

It has a stricter mode for packages an AI coding agent suggested. Agents sometimes recommend packages that don't exist, and attackers register those hallucinated names with malicious code ("slopsquatting"). A human picking a package and an agent picking one carry different risk, so depgate treats them differently.

No dependencies beyond the Python standard library (3.11+). A supply-chain tool shouldn't widen your own supply chain.

## Quick start

```bash
pip install -e .

depgate requests                     # check the latest version
depgate requests==2.32.3             # check a specific version
depgate --agent some-package         # stricter policy for agent-proposed packages
depgate -r requirements.txt --agent  # check a whole file
depgate -r requirements.txt --json   # machine-readable output for CI
```

Example:

```
BLOCK  reqeusts  [agent]
  X exists: 'reqeusts' does not exist on PyPI. An AI agent proposed a package
    that does not exist (possible hallucination). Did you mean: requests?

FLAG   jvhub==0.1.0  [default]
  ! project-age: Project first published 0 days ago (flag under 90).
  ! release-age: Version 0.1.0 was published 0.0 days ago (cooldown 3 days).
  ! history: Only 1 release(s) published (expect at least 3).
```

## Exit codes

| Code | Verdict | Meaning |
|---|---|---|
| 0 | allow | Nothing concerning found |
| 1 | flag | A person should look before it goes in |
| 2 | block | Do not admit |

With several packages, the exit code is the worst verdict. In CI, fail on `2` and require review on `1`.

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
| `provenance` | PyPI attestations (Trusted Publishing): which repo and CI workflow built the release. | info | flag, unless established |
| `metadata` | Project lists a source repository or homepage. | info | flag |

"Established" means at least 730 days old **and** at least 10 releases. Most long-standing packages predate PyPI attestations, so a missing attestation on an established project is reported but not counted against it.

When attestations exist, depgate reports the publisher, for example `GitHub:psf/requests`. That tells you which repository's CI produced the file, not just who uploaded it.

## Tuning

Copy `depgate.example.toml`, change what you need, and pass it with `--policy`. Each table overrides one profile; anything you leave out keeps its built-in value. Unknown keys are rejected so typos in the policy file don't fail silently.

```bash
depgate --policy depgate.toml --agent -r requirements.txt
```

The typosquat check compares against a built-in snapshot of popular packages. For production, point `popular_file` at a fresh list (one name per line).

## Limitations (v0)

- PyPI only.
- Version ranges like `flask>=3.0` are checked against the latest release, not resolved. Pin versions for accurate results.
- Attestations are checked for presence and publisher, but not cryptographically verified. Verification (for example with `pypi-attestations`) is planned.
- No vulnerability lookup yet (OSV is the obvious next source).
- Does not inspect package contents.

## Tests

```bash
python -m unittest discover -s tests
```

The tests use a fake PyPI and need no network access.
