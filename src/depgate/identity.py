"""Build identity: where a release was built, read from its signing certificate.

Every PEP 740 attestation carries a short-lived Sigstore (Fulcio) certificate.
Fulcio records the CI build's identity in X.509 extensions under the arc
1.3.6.1.4.1.57264.1 (see sigstore/fulcio docs/oid-info.md): the git ref,
the event that triggered the build, the runner type, the workflow, the
deployment environment, the repository's permanent numeric ID, and more.

Trusted Publishing only pins the repository, workflow filename and optional
environment. It does not pin the ref, so a copy of the release workflow on a
throwaway branch can publish a release whose attestation verifies (the
Red Hat npm compromise, June 2026). This module reads the full identity so
depgate can compare a release with the package's own history.

Parsing uses only the standard library (a minimal DER reader). The values
are only trustworthy when the attestation itself was verified; callers
must track that.
"""

from __future__ import annotations

import base64
import re
from dataclasses import asdict, dataclass

FULCIO_ARC = "1.3.6.1.4.1.57264.1."

# OID suffix -> field name. Deprecated GitHub-only OIDs (.2-.6) are used only
# as fallbacks for certificates issued before the generic ones existed.
OIDS = {
    "8": "issuer",
    "9": "build_signer_uri",
    "10": "build_signer_digest",
    "11": "runner_environment",
    "12": "source_repo_uri",
    "13": "source_repo_digest",
    "14": "source_repo_ref",
    "15": "source_repo_id",
    "16": "source_repo_owner_uri",
    "17": "source_repo_owner_id",
    "18": "build_config_uri",
    "19": "build_config_digest",
    "20": "build_trigger",
    "21": "run_invocation_uri",
    "22": "source_repo_visibility",
    "23": "deployment_environment",
}
LEGACY = {"2": "build_trigger", "3": "source_repo_digest", "5": "legacy_repository", "6": "source_repo_ref"}


# ---------- minimal DER reader ----------

class DERError(ValueError):
    pass


def _read_tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """Return (tag, content_start, content_end) for the element at pos."""
    if pos + 2 > len(data):
        raise DERError("truncated element")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise DERError("bad length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    end = pos + length
    if end > len(data):
        raise DERError("element overruns buffer")
    return tag, pos, end


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out, pos = [], start
    while pos < end:
        tag, cs, ce = _read_tlv(data, pos)
        out.append((tag, cs, ce))
        pos = ce
    return out


def _decode_oid(raw: bytes) -> str:
    if not raw:
        raise DERError("empty OID")
    first = raw[0]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    value = 0
    for b in raw[1:]:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(value)
            value = 0
    return ".".join(map(str, parts))


def certificate_extensions(der: bytes) -> dict[str, bytes]:
    """OID -> raw extnValue contents, for every extension in an X.509 certificate."""
    tag, cs, ce = _read_tlv(der, 0)  # Certificate
    tbs_tag, ts, te = _children(der, cs, ce)[0]  # TBSCertificate
    for tag, s, e in _children(der, ts, te):
        if tag == 0xA3:  # [3] EXPLICIT Extensions
            _, xs, xe = _read_tlv(der, s)
            out = {}
            for _, es, ee in _children(der, xs, xe):
                parts = _children(der, es, ee)
                oid = _decode_oid(der[parts[0][1]:parts[0][2]])
                octet = parts[-1]  # extnValue is last (critical flag is optional)
                out[oid] = der[octet[1]:octet[2]]
            return out
    return {}


def _as_text(raw: bytes, legacy: bool) -> str:
    """Fulcio's generic extensions are DER UTF8String; the legacy ones are raw bytes."""
    if not legacy and raw and raw[0] == 0x0C:
        _, s, e = _read_tlv(raw, 0)
        raw = raw[s:e]
    return raw.decode("utf-8", "replace")


# ---------- identity ----------

@dataclass(frozen=True)
class BuildIdentity:
    issuer: str = ""
    build_signer_uri: str = ""
    build_signer_digest: str = ""
    runner_environment: str = ""
    source_repo_uri: str = ""
    source_repo_digest: str = ""
    source_repo_ref: str = ""
    source_repo_id: str = ""
    source_repo_owner_uri: str = ""
    source_repo_owner_id: str = ""
    build_config_uri: str = ""
    build_config_digest: str = ""
    build_trigger: str = ""
    run_invocation_uri: str = ""
    source_repo_visibility: str = ""
    deployment_environment: str = ""
    legacy_repository: str = ""

    # Derived, comparable views ------------------------------------------

    @property
    def repo(self) -> str:
        """owner/repo, lowercased."""
        uri = self.source_repo_uri or (f"https://github.com/{self.legacy_repository}" if self.legacy_repository else "")
        return _strip_host(uri).lower()

    @property
    def workflow(self) -> str:
        """Workflow file that started the build, without the @ref suffix."""
        return _workflow_path(self.build_config_uri)

    @property
    def signer_workflow(self) -> str:
        """Workflow file that signed (differs from `workflow` for reusable workflows)."""
        return _workflow_path(self.build_signer_uri)

    @property
    def ref_kind(self) -> str:
        """'tag', 'branch:<name>', or the raw ref."""
        ref = self.source_repo_ref
        if ref.startswith("refs/tags/"):
            return "tag"
        if ref.startswith("refs/heads/"):
            return "branch:" + ref[len("refs/heads/"):]
        return ref

    @property
    def ref_family(self) -> str:
        """ref_kind with digit runs collapsed, so per-version branches compare equal.

        'branch:release-9.2.0' and 'branch:release-9.1.1' are both
        'branch:release-#.#.#'; 'branch:maintenance/2.5.x' is
        'branch:maintenance/#.#.x'. Someone who can push a branch matching the
        pattern can still blend in; this check catches builds from somewhere
        the project never releases from.
        """
        return re.sub(r"\d+", "#", self.ref_kind)

    def to_dict(self) -> dict:
        d = {k: v for k, v in asdict(self).items() if v}
        d.update(repo=self.repo, workflow=self.workflow, ref_kind=self.ref_kind)
        return d


def _strip_host(uri: str) -> str:
    for prefix in ("https://github.com/", "https://gitlab.com/"):
        if uri.startswith(prefix):
            return uri[len(prefix):]
    return uri


def _workflow_path(uri: str) -> str:
    """'https://github.com/o/r/.github/workflows/release.yml@refs/tags/v1' -> 'o/r/.github/workflows/release.yml'."""
    return _strip_host(uri).split("@", 1)[0].lower()


def from_certificate(der: bytes) -> BuildIdentity:
    exts = certificate_extensions(der)
    values: dict[str, str] = {}
    for oid, raw in exts.items():
        if not oid.startswith(FULCIO_ARC):
            continue
        suffix = oid[len(FULCIO_ARC):]
        if suffix in OIDS:
            values[OIDS[suffix]] = _as_text(raw, legacy=False)
    for oid, raw in exts.items():  # fallbacks for old certificates
        suffix = oid[len(FULCIO_ARC):] if oid.startswith(FULCIO_ARC) else ""
        if suffix in LEGACY and LEGACY[suffix] not in values:
            values[LEGACY[suffix]] = _as_text(raw, legacy=True)
    return BuildIdentity(**values)


def from_provenance(provenance: dict) -> list[BuildIdentity]:
    """Identities of every attestation in a PyPI provenance object (unverified)."""
    out = []
    for bundle in provenance.get("attestation_bundles") or []:
        for att in bundle.get("attestations") or []:
            cert = (att.get("verification_material") or {}).get("certificate")
            if not cert:
                continue
            try:
                out.append(from_certificate(base64.b64decode(cert)))
            except (DERError, ValueError, IndexError):
                continue  # unparseable certificates are left to signature verification
    return out


# ---------- comparison with history ----------

# (field label, how to read it, why a change matters)
COMPARED = [
    ("ref", lambda i: i.ref_family, "git ref the release was built from"),
    ("trigger", lambda i: i.build_trigger, "event that started the build"),
    ("workflow", lambda i: i.workflow, "workflow file that started the build"),
    ("signer", lambda i: i.signer_workflow, "workflow that signed the release"),
    ("runner", lambda i: i.runner_environment, "runner type"),
    ("environment", lambda i: i.deployment_environment, "deployment environment"),
    ("visibility", lambda i: i.source_repo_visibility, "repository visibility at signing"),
]


@dataclass
class Change:
    field: str
    level: str  # "flag" or "block" or "info"
    message: str


def compare(current: BuildIdentity, history: list[tuple[str, BuildIdentity]]) -> list[Change]:
    """Differences between a release's identity and identities seen in earlier releases.

    `history` is [(version, identity)], newest first. Tags are compared by kind
    only (every release has a new tag); branches by name.
    """
    changes: list[Change] = []
    if not history:
        return changes
    past = [h for _, h in history]
    versions = ", ".join(v for v, _ in history)

    # Repository: numeric IDs survive renames and transfers but not re-creation.
    past_ids = {h.source_repo_id for h in past if h.source_repo_id}
    past_repos = {h.repo for h in past if h.repo}
    if current.source_repo_id and past_ids and current.source_repo_id not in past_ids:
        if current.repo in past_repos:
            changes.append(Change("repo-id", "block",
                f"Repository {current.repo} has a new numeric ID ({current.source_repo_id}; "
                f"was {', '.join(sorted(past_ids))}). The repo was deleted and re-created, possibly by someone else."))
        else:
            changes.append(Change("repo", "flag",
                f"Built from a different repository: {current.repo or '?'} (earlier releases: "
                f"{', '.join(sorted(past_repos)) or '?'})."))
    elif current.repo and past_repos and current.repo not in past_repos:
        if current.source_repo_id and current.source_repo_id in past_ids:
            changes.append(Change("repo", "info",
                f"Repository renamed or transferred to {current.repo} (same repository ID)."))
        elif not current.source_repo_id or not past_ids:
            changes.append(Change("repo", "flag",
                f"Built from a different repository: {current.repo} (earlier releases: {', '.join(sorted(past_repos))})."))

    past_owner_ids = {h.source_repo_owner_id for h in past if h.source_repo_owner_id}
    if current.source_repo_owner_id and past_owner_ids and current.source_repo_owner_id not in past_owner_ids:
        changes.append(Change("owner-id", "flag",
            f"Repository owner changed (owner ID {current.source_repo_owner_id}, was {', '.join(sorted(past_owner_ids))})."))

    for label, get, what in COMPARED:
        now_val = get(current)
        seen = {get(h) for h in past}
        if now_val in seen or not any(seen):
            continue
        before = ", ".join(sorted(v or "(none)" for v in seen))
        if label == "environment" and not now_val:
            msg = f"No deployment environment, but earlier releases used {before}."
        elif label == "runner" and now_val == "self-hosted":
            msg = f"Built on a self-hosted runner; earlier releases used {before}."
        elif label == "ref":
            msg = (f"Built from {current.source_repo_ref or '(no ref)'}, unlike earlier releases "
                   f"({', '.join(sorted({h.source_repo_ref for h in past if h.source_repo_ref}))[:200]}).")
        else:
            msg = f"New {what}: {now_val or '(none)'} (earlier releases: {before})."
        changes.append(Change(label, "flag", msg))

    if changes:
        run = f" Build run: {current.run_invocation_uri}" if current.run_invocation_uri else ""
        changes[-1].message += f" Compared with {versions}.{run}"
    return changes


def release_line(version: str) -> str:
    """'2.0.53' -> '2.0'; '1.14.1' -> '1.14'; '2026.5.1' -> '2026.5'."""
    nums = re.findall(r"\d+", version)
    return ".".join(nums[:2])


DROP_STREAK = 3   # unsigned releases in a row before "stopped signing" is assumed
DROP_LOOKBACK = DROP_STREAK + 3


def dropped(version: str, earlier: list[tuple[str, BuildIdentity | None]]) -> tuple[str, str] | None:
    """Judge a release that has no attestation. `earlier` is newest first, signed or not.

    Returns (level, message), or None when nothing earlier was signed.
    Unsigned releases right after signed ones are flagged until DROP_STREAK of
    them in a row; after that the project is taken to have stopped signing
    (info). A release line that was never signed (e.g. a maintenance branch
    built another way) is info too.
    """
    signed = [(v, i) for v, i in earlier if i]
    if not signed:
        return None
    line = release_line(version)
    same_line = [(v, i) for v, i in earlier if release_line(v) == line]
    if same_line and not any(i for _, i in same_line):
        return "info", (f"No attestation; the {line}.x line has never been signed here "
                        f"(other lines are, e.g. {signed[0][0]}).")
    scope = same_line or earlier
    streak = next((n for n, (_, i) in enumerate(scope) if i), len(scope))
    last_signed = next(v for v, i in scope if i) if any(i for _, i in scope) else signed[0][0]
    if streak >= DROP_STREAK:
        return "info", f"No attestation; the project stopped signing after {last_signed}."
    versions = ", ".join(v for v, _ in signed[:5])
    unsigned_since = f" {streak} unsigned release(s) since {last_signed}." if streak else ""
    return "flag", (f"This release has no attestation, but earlier releases were signed by "
                    f"{summarize(signed[0][1])} ({versions}). It was published outside the usual "
                    f"signed pipeline, for example with a leftover API token or a hijacked account.{unsigned_since}")


def fetch_parallel(fn, items, workers: int = 8) -> list:
    """Map fn over items with a small thread pool, keeping order."""
    items = list(items)
    if len(items) <= 1:
        return [fn(i) for i in items]
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(min(workers, len(items))) as pool:
        return list(pool.map(fn, items))


def summarize(identity: BuildIdentity) -> str:
    parts = [identity.repo or identity.build_signer_uri or identity.issuer or "unknown builder"]
    if identity.workflow:
        parts.append(identity.workflow.rsplit("/", 1)[-1])
    if identity.source_repo_ref:
        parts.append(identity.source_repo_ref)
    if identity.build_trigger:
        parts.append(f"on {identity.build_trigger}")
    if identity.deployment_environment:
        parts.append(f"env {identity.deployment_environment}")
    if identity.runner_environment:
        parts.append(identity.runner_environment)
    return ", ".join(parts)
