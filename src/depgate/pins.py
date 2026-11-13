"""Pinned build identities, and PEP 751 output.

A pins file records where each package's releases are expected to be built
(repository and its numeric ID, workflow, ref kind, trigger, runner,
environment). Keep it next to your lockfile and commit it. depgate then
reports any release whose build identity differs from the pin, even when the
package's own recent history has already drifted.

Format (JSON, so the core stays standard-library only):

    {"version": 1,
     "packages": {"sigstore": [{"source_repo_uri": "...", "source_repo_id": "...", ...}]}}

PEP 751 (pylock.toml) has `packages.attestation-identities`, which holds the
PyPI Trusted Publisher records (kind, repository, workflow, environment).
That is coarser than a pin (no ref, trigger, runner or repository ID), but
installers may enforce it, so depgate can print it too.
"""

from __future__ import annotations

import json
from pathlib import Path

from .identity import BuildIdentity
from .pypi import normalize

# Fields that change every release and so are never pinned.
PER_RUN = {"build_signer_digest", "source_repo_digest", "build_config_digest", "run_invocation_uri"}
KEPT = [f for f in BuildIdentity.__dataclass_fields__ if f not in PER_RUN]


def load(path: str) -> dict[str, list[dict]]:
    p = Path(path)
    if not p.exists():
        return {}
    data = json.loads(p.read_text())
    if data.get("version") != 1:
        raise ValueError(f"{path}: unsupported pins file version {data.get('version')!r}")
    return {normalize(k): v for k, v in (data.get("packages") or {}).items()}


def pin_entry(identity: dict) -> dict:
    return {k: identity[k] for k in KEPT if identity.get(k)}


def update(path: str, decisions) -> list[str]:
    """Add or replace pins for every decision that has a build identity. Returns pinned names."""
    pins = load(path)
    done = []
    for d in decisions:
        if d.identity:
            pins[normalize(d.package)] = [pin_entry(d.identity)]
            done.append(f"{d.package}=={d.version}")
    Path(path).write_text(json.dumps({"version": 1, "packages": dict(sorted(pins.items()))}, indent=2) + "\n")
    return done


def _toml_str(v: str) -> str:
    return json.dumps(v)  # JSON string escapes are valid TOML basic strings


def pep751(decisions) -> str:
    """pylock.toml snippets carrying each package's attestation identities."""
    out = []
    for d in decisions:
        if not d.attestation_identities:
            continue
        out.append(f"[[packages]]\nname = {_toml_str(d.package)}\nversion = {_toml_str(d.version or '')}")
        for pub in d.attestation_identities:
            out.append("[[packages.attestation-identities]]")
            out += [f"{k} = {_toml_str(str(v))}" for k, v in sorted(pub.items())]
        out.append("")
    return "\n".join(out)
