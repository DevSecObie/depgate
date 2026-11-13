"""Admission checks. Each check returns zero or more Findings."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import identity as identity_mod
from . import verify as verify_mod
from .policy import Policy
from .popular import POPULAR_SET
from .pypi import Project, PyPIClient, Release, normalize

INFO, FLAG, BLOCK = "info", "flag", "block"
RANK = {INFO: 0, FLAG: 1, BLOCK: 2}
ALLOW = "allow"

TYPO_AFFIXES_SUFFIX = ("-python", "-py", "-py3", "-lib", "-dev", "-sdk", "-api", "2", "3", "-official")
TYPO_AFFIXES_PREFIX = ("python-", "py-", "py", "python3-")


@dataclass
class Finding:
    check: str
    level: str
    message: str


@dataclass
class Decision:
    package: str
    version: str | None
    profile: str
    findings: list[Finding] = field(default_factory=list)
    # Build identity of this release (from its signing certificate), if any.
    identity: dict | None = None
    # PyPI Trusted Publisher records, in PEP 751 `attestation-identities` shape.
    attestation_identities: list[dict] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        levels = [f.level for f in self.findings if f.level != INFO]
        if not levels:
            return ALLOW
        return max(levels, key=RANK.__getitem__)

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "version": self.version,
            "profile": self.profile,
            "verdict": self.verdict,
            "findings": [f.__dict__ for f in self.findings],
            **({"identity": self.identity} if self.identity else {}),
            **({"attestation_identities": self.attestation_identities} if self.attestation_identities else {}),
        }


# ---------- helpers ----------

def _osa_distance(a: str, b: str) -> int:
    """Optimal string alignment distance (Levenshtein plus adjacent swaps)."""
    if abs(len(a) - len(b)) > 3:
        return 99
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def load_popular(policy: Policy) -> frozenset[str]:
    if policy.popular_file:
        names = Path(policy.popular_file).read_text().split()
        return frozenset(normalize(n) for n in names)
    return frozenset(normalize(n) for n in POPULAR_SET)


def lookalikes(name: str, popular: frozenset[str], max_distance: int) -> list[str]:
    """Popular packages this name imitates (empty if the name is itself popular)."""
    n = normalize(name)
    if n in popular:
        return []
    hits = set()
    for p in popular:
        # Short names produce too many accidental near matches.
        limit = max_distance if len(p) >= 5 else min(max_distance, 1)
        if len(p) < 3:
            continue
        if _osa_distance(n, p) <= limit:
            hits.add(p)
        # Affix tricks in both directions: "requests-python" or "dateutil" (for "python-dateutil").
        if any(n == p + s or p == n + s for s in TYPO_AFFIXES_SUFFIX):
            hits.add(p)
        if any(n == pre + p or p == pre + n for pre in TYPO_AFFIXES_PREFIX):
            hits.add(p)
    return sorted(hits)


def _age_days(when: datetime | None, now: datetime) -> float | None:
    return None if when is None else (now - when).total_seconds() / 86400


def _action(level: str) -> str | None:
    return None if level == "allow" else level


_GH_REPO = re.compile(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", re.I)


def _source_repos(project_urls: dict[str, str]) -> set[str]:
    """GitHub owner/repo pairs the project advertises in its metadata."""
    repos = set()
    for url in project_urls.values():
        m = _GH_REPO.search(url or "")
        if m:
            repo = m.group(2).removesuffix(".git")
            repos.add(f"{m.group(1)}/{repo}".lower())
    return repos


# ---------- main entry ----------

def evaluate(
    name: str,
    version: str | None,
    client: PyPIClient,
    policy: Policy,
    profile: str = "default",
    now: datetime | None = None,
    verify: bool = True,
    identity_only: bool = False,
    pins: dict | None = None,
) -> Decision:
    """Evaluate one package.

    identity_only: run only existence, version, provenance and build-identity
    checks, so depgate can sit beside other tools without repeating their alerts.
    pins: expected build identities by normalized package name (see pins.py).
    """
    now = now or datetime.now(timezone.utc)
    decision = Decision(package=name, version=version, profile=profile)
    add = decision.findings.append
    popular = load_popular(policy)

    project = client.project(name)
    looks_like = lookalikes(name, popular, policy.typo_max_distance)

    # 1. Existence
    if project is None:
        msg = f"'{name}' does not exist on PyPI."
        if profile == "agent":
            msg += " An AI agent proposed a package that does not exist (possible hallucination)."
        if looks_like:
            msg += f" Did you mean: {', '.join(looks_like)}?"
        add(Finding("exists", BLOCK, msg))
        return decision

    # Resolve which release we are admitting.
    target_version = version or project.latest_version
    decision.version = target_version
    release: Release | None = project.releases.get(target_version)
    if release is None or not release.files:
        add(Finding("version", BLOCK, f"Version {target_version} has no published files on PyPI."))
        return decision
    if release.yanked:
        add(Finding("version", BLOCK, f"Version {target_version} has been yanked by its maintainers."))

    age = _age_days(project.first_upload, now)
    if not identity_only:
        # 2. Typosquatting
        if looks_like:
            add(Finding(
                "typosquat", policy.typo_action,
                f"Name is very close to popular package(s): {', '.join(looks_like)}.",
            ))

        # 3. Project age
        if age is not None:
            if policy.project_age_block_days and age < policy.project_age_block_days:
                add(Finding("project-age", BLOCK,
                            f"Project first published {age:.0f} days ago (block under {policy.project_age_block_days})."))
            elif age < policy.project_age_flag_days:
                add(Finding("project-age", FLAG,
                            f"Project first published {age:.0f} days ago (flag under {policy.project_age_flag_days})."))

        # 4. Release age (cooldown for brand-new versions)
        r_age = _age_days(release.upload_time, now)
        if r_age is not None and r_age < policy.release_age_flag_days:
            add(Finding("release-age", FLAG,
                        f"Version {target_version} was published {r_age:.1f} days ago "
                        f"(cooldown {policy.release_age_flag_days} days)."))

        # 5. Release history
        if project.release_count < policy.min_releases:
            add(Finding("history", FLAG,
                        f"Only {project.release_count} release(s) published (expect at least {policy.min_releases})."))

        # 6. Install-time code execution
        if not release.has_wheel:
            level = _action(policy.sdist_only_action)
            if level:
                add(Finding("install-code", level,
                            "No wheel for this version; installing builds from source and runs the package's build code."))

    detail = client.release_detail(project.name, target_version)

    # 7. Known vulnerabilities (PyPI's per-version data, sourced from OSV)
    if detail and detail.vulnerabilities and not identity_only:
        # PyPI lists PYSEC and GHSA advisories separately; collapse ones sharing an ID or alias.
        unique, seen = [], set()
        for v in detail.vulnerabilities:
            keys = {v.id, *v.aliases}
            if keys & seen:
                continue
            seen |= keys
            unique.append(v)
        parts = []
        for v in unique[:5]:
            cve = next((a for a in [v.id, *v.aliases] if a.startswith("CVE-")), v.id)
            fixed = f" (fixed in {', '.join(v.fixed_in[:2])})" if v.fixed_in else ""
            parts.append(f"{cve}{fixed}")
        more = f", and {len(unique) - 5} more" if len(unique) > 5 else ""
        add(Finding("vulnerabilities", policy.vuln_action,
                    f"{len(unique)} known vulnerabilities: {', '.join(parts)}{more}."))

    # 8. Provenance (PEP 740 attestations from Trusted Publishing)
    provenances = {}
    for f in release.files:
        prov = client.provenance(project.name, target_version, f.filename)
        if prov:
            provenances[f.filename] = prov

    source_repos = _source_repos(project.project_urls)
    publishers: set[str] = set()
    verified_files: set[str] | None = None  # None = signatures not checked

    if provenances and verify and verify_mod.AVAILABLE and detail:
        state: dict = {}
        results = []
        for fname, prov in provenances.items():
            results += verify_mod.verify_provenance(fname, detail.digests.get(fname, ""), prov, state)
        failures = [r for r in results if not r.ok]
        verified_files = {r.filename for r in results if r.ok} - {r.filename for r in failures}
        publishers = {r.publisher for r in results if r.ok}
        if failures:
            first = failures[0]
            add(Finding("provenance", policy.attestation_invalid_action,
                        f"Attestation FAILED verification for {first.filename}: {first.error}"))
        else:
            root = " (bundled Sigstore trust root)" if state.get("offline") else ""
            add(Finding("provenance", INFO,
                        f"Signatures verified{root}: built by {', '.join(sorted(publishers))}."))
    elif provenances:
        for prov in provenances.values():
            for bundle in prov.get("attestation_bundles", []):
                publishers.add(verify_mod.describe_publisher(bundle.get("publisher") or {}))
        why = "verification disabled" if not verify else "install depgate[verify] to check signatures"
        add(Finding("provenance", INFO,
                    f"Attested by {', '.join(sorted(publishers))} (not cryptographically verified: {why})."))

    # 9. Publisher must match the repository the project claims as its source
    gh_publishers = {p.split(":", 1)[1].lower() for p in publishers if p.lower().startswith("github:")}
    if gh_publishers and source_repos and not (gh_publishers & source_repos):
        built, claimed = ", ".join(sorted(gh_publishers)), ", ".join(sorted(source_repos))
        same_owner = {p.split("/")[0] for p in gh_publishers} & {s.split("/")[0] for s in source_repos}
        if same_owner:
            # e.g. numpy builds releases from numpy/numpy-release; same org, separate repo.
            add(Finding("publisher-mismatch", INFO,
                        f"Built by {built}, a different repo in the same organization as {claimed}."))
        else:
            add(Finding("publisher-mismatch", policy.publisher_mismatch_action,
                        f"Built by {built}, but project metadata points to {claimed} (different owner)."))

    # 9b. Build identity: compare where this release was built with earlier releases
    if provenances:
        _check_identity(decision, project, release, provenances, verified_files, client, policy, pins)

    if not provenances:
        established = (
            age is not None
            and age >= policy.established_age_days
            and project.release_count >= policy.established_min_releases
        )
        level = INFO if established else policy.no_provenance_action
        note = " Established project, so not counted against it." if established and policy.no_provenance_action != INFO else ""
        add(Finding("provenance", level,
                    "No PyPI attestations; cannot verify which source repo and CI built this release." + note))
        # Earlier releases were signed but this one isn't: published outside the usual pipeline,
        # e.g. with a leftover API token (Ultralytics 8.3.45/8.3.46, December 2024).
        # A few predecessors are enough to judge a drop; don't scan deep history for never-signed packages.
        judged = identity_mod.dropped(target_version, _earlier(project, release, client, policy,
                                                               limit=identity_mod.DROP_LOOKBACK))
        if judged:
            level, msg = judged
            add(Finding("attestation-dropped", policy.attestation_dropped_action if level == "flag" else INFO, msg))

    # 10. Source link
    if identity_only:
        return decision
    urls = {k.lower(): v for k, v in project.project_urls.items()}
    if not any(k in urls for k in ("source", "source code", "repository", "homepage", "github", "code")):
        level = policy.no_source_url_action
        add(Finding("metadata", level, "No source repository or homepage URL in project metadata."))

    return decision


# ---------- build identity ----------

def _pick_file(release: Release):
    wheels = [f for f in release.files if f.packagetype == "bdist_wheel"]
    return (wheels or release.files)[0]


def _history(project: Project, release: Release, client: PyPIClient, policy: Policy):
    """[(version, identity)] for the newest earlier releases that carry attestations.

    Earlier releases are read from PyPI's stored attestations, which PyPI
    verified when they were uploaded.
    """
    return [h for h in _earlier(project, release, client, policy) if h[1]][: policy.identity_history]


def _earlier(project: Project, release: Release, client: PyPIClient, policy: Policy, limit: int | None = None):
    """[(version, identity or None)] for the newest earlier releases, newest first. Fetched in parallel."""
    if not release.upload_time:
        return []
    earlier = sorted(
        (r for r in project.releases.values()
         if r.files and r.upload_time and r.upload_time < release.upload_time and not r.yanked),
        key=lambda r: r.upload_time, reverse=True,
    )[: limit or policy.identity_lookback]

    def one(r: Release):
        prov = client.provenance(project.name, r.version, _pick_file(r).filename)
        ids = identity_mod.from_provenance(prov) if prov else []
        return (r.version, ids[0] if ids else None)

    return identity_mod.fetch_parallel(one, earlier)


def identity_findings(decision: Decision, current: list, history: list, pins: dict | None,
                      pin_key: str, policy: Policy, unverified: str) -> None:
    """Shared by PyPI and npm: compare a release's identity with history and pins."""
    add = decision.findings.append
    ident = current[0]
    decision.identity = ident.to_dict()

    # Files of one release should all come from the same build.
    shapes = {(i.repo, i.workflow, i.ref_kind, i.build_trigger, i.runner_environment, i.deployment_environment)
              for i in current}
    if len(shapes) > 1:
        add(Finding("build-identity", _level("flag", policy),
                    f"Files in this release were built by {len(shapes)} different builds: "
                    + "; ".join(identity_mod.summarize(i) for i in current[:3]) + "."))

    changes = identity_mod.compare(ident, history)
    for c in changes:
        add(Finding("build-identity", _level(c.level, policy), c.message + unverified))
    if not history:
        add(Finding("build-identity", INFO,
                    f"Built from {identity_mod.summarize(ident)}{unverified}. "
                    "No earlier signed releases to compare with."))
    elif not [c for c in changes if c.level != "info"]:
        add(Finding("build-identity", INFO,
                    f"Built from {identity_mod.summarize(ident)}{unverified}; "
                    f"matches the {len(history)} earlier signed release(s)."))

    pinned = (pins or {}).get(pin_key)
    if pinned:
        expected = [("pinned identity", identity_mod.BuildIdentity(**p)) for p in pinned]
        pin_changes = identity_mod.compare(ident, expected)
        for c in pin_changes:
            add(Finding("identity-pin", _level(c.level, policy), c.message + unverified))
        if not pin_changes:
            add(Finding("identity-pin", INFO, "Matches the pinned build identity."))


def _level(change_level: str, policy: Policy) -> str:
    if change_level == "block":
        return policy.identity_repo_replaced_action
    if change_level == "flag":
        return policy.identity_change_action
    return INFO


def _check_identity(decision, project, release, provenances, verified_files, client, policy, pins):
    current: list[identity_mod.BuildIdentity] = []
    seen_publishers = []
    for fname, prov in provenances.items():
        if verified_files is not None and fname not in verified_files:
            continue  # a failed signature is already reported; don't trust its certificate or publisher
        for bundle in prov.get("attestation_bundles") or []:
            pub = {k: v for k, v in (bundle.get("publisher") or {}).items() if v is not None}
            if pub and pub not in seen_publishers:
                seen_publishers.append(pub)
        current += identity_mod.from_provenance(prov)
    decision.attestation_identities = seen_publishers
    if not current:
        return
    unverified = "" if verified_files is not None else " (read from an unverified attestation)"
    history = _history(project, release, client, policy)
    identity_findings(decision, current, history, pins, normalize(project.name), policy, unverified)


# ---------- npm (build identity only) ----------

def evaluate_npm(
    name: str,
    version: str | None,
    client,
    policy: Policy,
    profile: str = "default",
    verify: bool = True,
    pins: dict | None = None,
) -> Decision:
    """Build-identity checks for an npm package. Other npm checks are left to other tools."""
    from . import npm as npm_mod

    decision = Decision(package=f"npm:{name}", version=version, profile=profile)
    add = decision.findings.append
    pkg = client.package(name)
    if pkg is None:
        add(Finding("exists", BLOCK, f"'{name}' does not exist on npm."))
        return decision
    target, note = npm_mod.resolve(pkg, version)
    if target is None:
        # Can't tell which version npm would install: say so rather than check the wrong one.
        add(Finding("version", FLAG if "cannot resolve" in note else BLOCK, f"{note[0].upper()}{note[1:]}."))
        return decision
    decision.version = target
    info = pkg.versions.get(target)
    if info is None:
        add(Finding("version", BLOCK, f"Version {target} is not published on npm."))
        return decision
    if note:
        add(Finding("version", INFO, f"Checking {target}{note}."))

    earlier = sorted(
        (v for v in pkg.versions.values() if v.published and info.published and v.published < info.published),
        key=lambda v: v.published, reverse=True,
    )[: policy.identity_lookback]

    def one(v):
        if not v.has_attestations:
            return (v.version, None)
        return (v.version, npm_mod.bundle_identity(client.provenance_bundle(pkg.name, v.version) or {}))

    earlier_ids = identity_mod.fetch_parallel(one, earlier)
    history = [h for h in earlier_ids if h[1]][: policy.identity_history]

    bundle = client.provenance_bundle(pkg.name, target) if info.has_attestations else None
    if not bundle:
        add(Finding("provenance", INFO, "No npm provenance attestation on this version."))
        judged = identity_mod.dropped(target, earlier_ids)
        if judged:
            level, msg = judged
            add(Finding("attestation-dropped", policy.attestation_dropped_action if level == "flag" else INFO, msg))
        return decision

    unverified = " (read from an unverified attestation)"
    if verify and npm_mod.VERIFY_AVAILABLE:
        state: dict = {}
        error = npm_mod.verify_bundle(bundle, info.integrity, state)
        if error:
            add(Finding("provenance", policy.attestation_invalid_action,
                        f"Provenance attestation FAILED verification: {error}"))
            return decision
        root = " (bundled Sigstore trust root)" if state.get("offline") else ""
        add(Finding("provenance", INFO, f"Provenance signature verified{root}; it attests this exact tarball."))
        unverified = ""
    else:
        why = "verification disabled" if not verify else "install depgate[verify] to check signatures"
        add(Finding("provenance", INFO, f"npm provenance present (not cryptographically verified: {why})."))

    ident = npm_mod.bundle_identity(bundle)
    if ident:
        identity_findings(decision, [ident], history, pins, normalize(f"npm:{pkg.name}"), policy, unverified)
    return decision
