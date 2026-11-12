"""Policy: thresholds that decide flag vs block.

Two built-in profiles:
  default  - a human proposed the dependency
  agent    - an AI agent proposed it; stricter, because agents can
             hallucinate package names that attackers then register
             ("slopsquatting").

Override any value with a TOML file (see depgate.example.toml).
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, fields, replace
from pathlib import Path


@dataclass(frozen=True)
class Policy:
    # Project age: younger than block_days -> BLOCK, younger than flag_days -> FLAG.
    project_age_flag_days: int = 90
    project_age_block_days: int = 0  # 0 = never block on age alone

    # The specific version being admitted ("cooldown" for fresh releases).
    release_age_flag_days: int = 3

    # Very short release history.
    min_releases: int = 3

    # Typosquatting: edit distance to a popular name that triggers a finding.
    typo_max_distance: int = 1
    typo_action: str = "flag"  # "flag" or "block"

    # Release ships only an sdist, so install runs the package's build code.
    sdist_only_action: str = "flag"  # "flag", "block", or "info"

    # No PyPI attestations (Trusted Publishing provenance) on the release.
    no_provenance_action: str = "info"  # "flag", "block", or "info"

    # Established projects (old enough AND many releases) are not penalized for
    # missing attestations, since most long-standing packages predate them.
    established_age_days: int = 730
    established_min_releases: int = 10

    # Project has no source/homepage URL in its metadata.
    no_source_url_action: str = "info"

    # Optional path to a newline-separated list of popular package names.
    popular_file: str | None = None


DEFAULT = Policy()

AGENT = replace(
    DEFAULT,
    project_age_flag_days=180,
    project_age_block_days=30,
    release_age_flag_days=7,
    min_releases=5,
    typo_max_distance=2,
    typo_action="block",
    sdist_only_action="flag",
    no_provenance_action="flag",
    no_source_url_action="flag",
)

PROFILES = {"default": DEFAULT, "agent": AGENT}


def load(profile: str, path: str | None = None) -> Policy:
    """Load a built-in profile, then apply overrides from a TOML file.

    The TOML file may contain a [default] and/or [agent] table; values in
    the table matching the active profile override the built-in values.
    """
    base = PROFILES[profile]
    if not path:
        return base
    data = tomllib.loads(Path(path).read_text())
    overrides = data.get(profile, {})
    known = {f.name for f in fields(Policy)}
    unknown = set(overrides) - known
    if unknown:
        raise ValueError(f"unknown policy keys in [{profile}]: {', '.join(sorted(unknown))}")
    return replace(base, **overrides)
