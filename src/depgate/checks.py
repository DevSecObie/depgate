"""Admission checks. Each check returns zero or more Findings."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

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
) -> Decision:
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

    # 2. Typosquatting
    if looks_like:
        add(Finding(
            "typosquat", policy.typo_action,
            f"Name is very close to popular package(s): {', '.join(looks_like)}.",
        ))

    # 3. Project age
    age = _age_days(project.first_upload, now)
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
    if detail and detail.vulnerabilities:
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

    if provenances and verify and verify_mod.AVAILABLE and detail:
        state: dict = {}
        results = []
        for fname, prov in provenances.items():
            results += verify_mod.verify_provenance(fname, detail.digests.get(fname, ""), prov, state)
        failures = [r for r in results if not r.ok]
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

    # 10. Source link
    urls = {k.lower(): v for k, v in project.project_urls.items()}
    if not any(k in urls for k in ("source", "source code", "repository", "homepage", "github", "code")):
        level = policy.no_source_url_action
        add(Finding("metadata", level, "No source repository or homepage URL in project metadata."))

    return decision
