"""Cryptographic verification of PyPI attestations (PEP 740).

Optional: requires the `pypi-attestations` package
(`pip install 'depgate[verify]'`). Without it, depgate still reports
whether attestations exist, but cannot confirm they are genuine.

What "verified" means here: the Sigstore signature on the attestation is
valid, the signing certificate was issued to the Trusted Publisher PyPI
recorded (for example a specific GitHub repository and workflow), and the
attested digest matches the sha256 PyPI reports for the file.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

# sigstore/tuf log every offline trust-root load; keep the CLI output clean.
for _name in ("sigstore", "tuf", "securesystemslib"):
    logging.getLogger(_name).setLevel(logging.ERROR)

try:  # optional dependency
    from pypi_attestations import Distribution, Provenance

    AVAILABLE = True
except ImportError:  # pragma: no cover - exercised when extra not installed
    AVAILABLE = False


@dataclass
class FileResult:
    filename: str
    ok: bool
    publisher: str = ""
    error: str = ""


@dataclass
class VerifyResult:
    files: list[FileResult] = field(default_factory=list)
    offline_trust_root: bool = False

    @property
    def failures(self) -> list[FileResult]:
        return [f for f in self.files if not f.ok]

    @property
    def publishers(self) -> set[str]:
        return {f.publisher for f in self.files if f.ok and f.publisher}


def describe_publisher(pub: dict) -> str:
    repo = pub.get("repository") or pub.get("project") or "unknown"
    return f"{pub.get('kind', 'publisher')}:{repo}"


def _verify_one(attestation, publisher, dist, offline: bool) -> None:
    attestation.verify(publisher, dist, offline=offline)


def verify_provenance(filename: str, sha256: str, provenance: dict, state: dict) -> list[FileResult]:
    """Verify every attestation in one file's provenance object.

    `state` is shared across calls so that once the online Sigstore trust
    root is found unreachable, later files go straight to the bundled one.
    """
    results: list[FileResult] = []
    try:
        prov = Provenance.model_validate(provenance)
    except Exception as e:  # malformed provenance is itself a failure
        return [FileResult(filename, False, error=f"malformed provenance: {e}")]

    dist = Distribution(name=filename, digest=sha256)
    for bundle in prov.attestation_bundles:
        pub_desc = describe_publisher(bundle.publisher.model_dump())
        for att in bundle.attestations:
            try:
                try:
                    _verify_one(att, bundle.publisher, dist, offline=state.get("offline", False))
                except Exception as e:
                    # Trust-root refresh failures are network problems, not forgery.
                    if "TUF" in type(e).__name__ and not state.get("offline"):
                        state["offline"] = True
                        _verify_one(att, bundle.publisher, dist, offline=True)
                    else:
                        raise
                results.append(FileResult(filename, True, publisher=pub_desc))
            except Exception as e:
                results.append(FileResult(filename, False, publisher=pub_desc,
                                          error=f"{type(e).__name__}: {str(e)[:200]}"))
    return results
