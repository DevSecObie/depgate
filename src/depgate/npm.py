"""npm: build-identity checks only.

depgate complements the tools that already cover npm well (Socket, Aikido,
trustdiff, npm's own `min-release-age`, provenance-downgrade checks). For
npm it only checks what they don't: whether a release was built where the
package's earlier releases were (git ref, trigger, workflow, runner,
environment, repository ID), using the Sigstore certificate in the
release's SLSA provenance attestation.

Data:
  packument     https://registry.npmjs.org/<name>
  attestations  https://registry.npmjs.org/-/npm/v1/attestations/<name>@<version>

Signature verification uses the optional `sigstore` package (installed with
`depgate[verify]`): the bundle's signature and transparency-log entry are
checked, and the attested sha512 must match the tarball's `dist.integrity`.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime

from . import identity as identity_mod
from .pypi import USER_AGENT

REGISTRY = "https://registry.npmjs.org"

for _name in ("sigstore", "tuf", "securesystemslib"):
    logging.getLogger(_name).setLevel(logging.ERROR)

try:  # optional
    from sigstore.models import Bundle
    from sigstore.verify import Verifier
    from sigstore.verify import policy as sigstore_policy

    VERIFY_AVAILABLE = True
except ImportError:  # pragma: no cover
    VERIFY_AVAILABLE = False


def http_fetch(url: str, timeout: float = 20.0) -> "tuple[int, dict | None]":
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, None


def encode_name(name: str) -> str:
    """'@scope/pkg' -> '@scope%2fpkg' (the registry's URL form)."""
    return urllib.parse.quote(name, safe="@")


def parse_spec(spec: str) -> tuple[str, str | None]:
    """'@scope/pkg@1.2.3' -> ('@scope/pkg', '1.2.3'); '@scope/pkg@^1.2' -> ('@scope/pkg', '^1.2').

    The part after the name is returned as written; resolve() turns ranges and
    dist-tags into the version npm would install.
    """
    at = spec.find("@", 1)
    if at > 0:
        return spec[:at], spec[at + 1:] or None
    return spec, None


_SEMVER = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def _key(version: str):
    m = _SEMVER.match(version)
    if not m:
        return None
    major, minor, patch, pre = m.groups()
    return (int(major), int(minor), int(patch), 0 if pre else 1, pre or "")


def _satisfies(version: str, rng: str) -> bool | None:
    """Simple npm ranges: exact, ^, ~, x-ranges / partials, >=, *. None when unsupported."""
    k = _key(version)
    if k is None:
        return False
    if k[3] == 0 and not re.search(r"-", rng):
        return False  # npm skips prereleases unless the range names one
    rng = rng.strip().lstrip("=v").strip()
    if rng in ("", "*", "x", "X"):
        return True
    if rng.startswith(">="):
        lo = _key(rng[2:].strip().lstrip("v"))
        return None if lo is None else k >= lo
    op = rng[0] if rng[0] in "^~" else ""
    body = rng[len(op):].lstrip("v")
    parts = re.split(r"\.", body.split("-")[0])
    if not parts or not all(re.fullmatch(r"\d+|[xX*]", p) for p in parts) or len(parts) > 3:
        return None
    nums = [int(p) for p in parts if p.isdigit()]
    fixed = len(nums) if all(p.isdigit() for p in parts[:len(nums)]) else 0
    if op == "" and fixed == 3:
        return k[:3] == tuple(nums) and (k[3] == 1 or body == version)
    base = tuple(nums + [0] * (3 - len(nums)))
    if k[:3] < base:
        return False
    if op == "^":
        # Locks the first non-zero component among those given.
        lock = next((i for i, n in enumerate(nums) if n != 0), len(nums) - 1) + 1
        return k[:lock] == base[:lock]
    if op == "~":
        return k[:max(1, min(2, fixed))] == base[:max(1, min(2, fixed))]
    return k[:fixed] == base[:fixed]  # partial / x-range


def resolve(pkg: "NpmPackage", wanted: str | None, dist_tags: dict | None = None) -> tuple[str | None, str]:
    """(version npm would pick, note). Version None with a note when it can't tell."""
    if not wanted:
        return pkg.latest, ""
    if wanted in pkg.versions:
        return wanted, ""
    tags = dist_tags if dist_tags is not None else pkg.dist_tags
    if wanted in tags:
        return tags[wanted], f" (dist-tag '{wanted}')"
    matches = []
    for v in pkg.versions:
        ok = _satisfies(v, wanted)
        if ok is None:
            return None, f"cannot resolve range '{wanted}'"
        if ok:
            matches.append(v)
    if not matches:
        return None, f"no published version matches '{wanted}'"
    # npm prefers the latest tag when it satisfies the range.
    if pkg.latest in matches:
        return pkg.latest, f" (resolved from '{wanted}')"
    return max(matches, key=_key), f" (resolved from '{wanted}')"


@dataclass
class NpmVersion:
    version: str
    published: datetime | None
    integrity: str
    has_attestations: bool


@dataclass
class NpmPackage:
    name: str
    latest: str
    versions: dict[str, NpmVersion] = field(default_factory=dict)
    dist_tags: dict[str, str] = field(default_factory=dict)


def _time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class NpmClient:
    def __init__(self, fetch=http_fetch, base: str = REGISTRY):
        self.fetch = fetch
        self.base = base.rstrip("/")
        self._cache: dict[str, "tuple[int, dict | None]"] = {}

    def _get(self, url: str):
        if url not in self._cache:
            self._cache[url] = self.fetch(url)
        return self._cache[url]

    def package(self, name: str) -> NpmPackage | None:
        status, data = self._get(f"{self.base}/{encode_name(name)}")
        if status != 200 or not data or "versions" not in data:
            return None
        times = data.get("time") or {}
        versions = {}
        for v, meta in (data.get("versions") or {}).items():
            dist = meta.get("dist") or {}
            prov = ((dist.get("attestations") or {}).get("provenance") or {}).get("predicateType", "")
            versions[v] = NpmVersion(v, _time(times.get(v)), dist.get("integrity", ""), "slsa.dev/provenance" in prov)
        tags = data.get("dist-tags") or {}
        return NpmPackage(data.get("name", name), tags.get("latest", ""), versions, dict(tags))

    def provenance_bundle(self, name: str, version: str) -> dict | None:
        """The Sigstore bundle of the SLSA provenance attestation, if any."""
        status, data = self._get(f"{self.base}/-/npm/v1/attestations/{encode_name(name)}@{version}")
        if status != 200 or not data:
            return None
        for att in data.get("attestations") or []:
            if "slsa.dev/provenance" in att.get("predicateType", ""):
                return att.get("bundle")
        return None


def bundle_certificate(bundle: dict) -> bytes | None:
    vm = (bundle or {}).get("verificationMaterial") or {}
    raw = (vm.get("certificate") or {}).get("rawBytes")
    if not raw:
        chain = (vm.get("x509CertificateChain") or {}).get("certificates") or []
        raw = chain[0].get("rawBytes") if chain else None
    return base64.b64decode(raw) if raw else None


def bundle_identity(bundle: dict) -> identity_mod.BuildIdentity | None:
    der = bundle_certificate(bundle)
    if not der:
        return None
    try:
        return identity_mod.from_certificate(der)
    except (identity_mod.DERError, ValueError, IndexError):
        return None


def integrity_hex(integrity: str) -> str:
    """'sha512-<base64>' -> hex digest; '' when missing, not sha512, or malformed."""
    if not integrity.startswith("sha512-"):
        return ""
    try:
        return base64.b64decode(integrity[len("sha512-"):], validate=True).hex()
    except ValueError:
        return ""


def verify_bundle(bundle: dict, integrity: str, state: dict) -> str | None:
    """None if the bundle verifies and attests this tarball; otherwise an error message."""
    try:
        b = Bundle.from_json(json.dumps(bundle))
        try:
            verifier = state.get("verifier") or Verifier.production(offline=state.get("offline", False))
            _, payload = verifier.verify_dsse(b, sigstore_policy.UnsafeNoOp())
        except Exception as e:
            if "TUF" in type(e).__name__ and not state.get("offline"):
                state["offline"] = True
                verifier = Verifier.production(offline=True)
                _, payload = verifier.verify_dsse(b, sigstore_policy.UnsafeNoOp())
            else:
                raise
        state["verifier"] = verifier
    except Exception as e:
        return f"{type(e).__name__}: {str(e)[:200]}"
    want = integrity_hex(integrity)
    if not want:
        return "the registry gives no sha512 integrity for this tarball, so the attestation can't be tied to it"
    subjects = json.loads(payload).get("subject") or []
    if not any((s.get("digest") or {}).get("sha512") == want for s in subjects):
        return "attested sha512 does not match the tarball's integrity"
    return None
