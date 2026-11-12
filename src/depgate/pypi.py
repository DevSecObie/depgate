"""Thin PyPI client using only the standard library.

Uses the public JSON API (https://pypi.org/pypi/<name>/json) and the
Integrity API for attestations
(https://pypi.org/integrity/<name>/<version>/<filename>/provenance).
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

PYPI = "https://pypi.org"
USER_AGENT = "depgate/0.1 (+dependency admission gate)"

# A fetcher takes a URL and returns (status_code, parsed_json_or_None).
Fetcher = Callable[[str], "tuple[int, dict | None]"]


def normalize(name: str) -> str:
    """PEP 503 name normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


def http_fetch(url: str, timeout: float = 15.0) -> "tuple[int, dict | None]":
    headers = {"User-Agent": USER_AGENT}
    if "/integrity/" in url:
        headers["Accept"] = "application/vnd.pypi.integrity.v1+json"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, None


@dataclass
class FileInfo:
    filename: str
    packagetype: str  # "bdist_wheel" or "sdist"
    upload_time: datetime | None
    yanked: bool


@dataclass
class Release:
    version: str
    files: list[FileInfo]

    @property
    def upload_time(self) -> datetime | None:
        times = [f.upload_time for f in self.files if f.upload_time]
        return min(times) if times else None

    @property
    def yanked(self) -> bool:
        return bool(self.files) and all(f.yanked for f in self.files)

    @property
    def has_wheel(self) -> bool:
        return any(f.packagetype == "bdist_wheel" for f in self.files)


@dataclass
class Project:
    name: str
    latest_version: str
    summary: str
    project_urls: dict[str, str]
    releases: dict[str, Release] = field(default_factory=dict)

    @property
    def first_upload(self) -> datetime | None:
        times = [r.upload_time for r in self.releases.values() if r.upload_time]
        return min(times) if times else None

    @property
    def release_count(self) -> int:
        # Count only releases that actually have files.
        return sum(1 for r in self.releases.values() if r.files)


@dataclass
class Vulnerability:
    id: str
    aliases: list[str]
    summary: str
    fixed_in: list[str]
    withdrawn: bool = False


@dataclass
class ReleaseDetail:
    digests: dict[str, str]  # filename -> sha256
    vulnerabilities: list[Vulnerability]


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _parse_files(items: list[dict]) -> list[FileInfo]:
    return [
        FileInfo(
            filename=i["filename"],
            packagetype=i.get("packagetype", ""),
            upload_time=_parse_time(i.get("upload_time_iso_8601")),
            yanked=bool(i.get("yanked", False)),
        )
        for i in items
    ]


class PyPIClient:
    def __init__(self, fetch: Fetcher = http_fetch, base: str = PYPI):
        self.fetch = fetch
        self.base = base.rstrip("/")
        self._cache: dict[str, "tuple[int, dict | None]"] = {}

    def _get(self, url: str) -> "tuple[int, dict | None]":
        if url not in self._cache:
            self._cache[url] = self.fetch(url)
        return self._cache[url]

    def project(self, name: str) -> Project | None:
        status, data = self._get(f"{self.base}/pypi/{normalize(name)}/json")
        if status == 404 or data is None:
            return None
        info = data.get("info", {})
        releases = {
            v: Release(version=v, files=_parse_files(files))
            for v, files in (data.get("releases") or {}).items()
        }
        return Project(
            name=info.get("name", name),
            latest_version=info.get("version", ""),
            summary=info.get("summary") or "",
            project_urls=info.get("project_urls") or {},
            releases=releases,
        )

    def release_detail(self, name: str, version: str) -> "ReleaseDetail | None":
        """Per-version data: file digests and known vulnerabilities (PyPI sources these from OSV)."""
        status, data = self._get(f"{self.base}/pypi/{normalize(name)}/{version}/json")
        if status != 200 or data is None:
            return None
        digests = {
            u["filename"]: (u.get("digests") or {}).get("sha256", "")
            for u in data.get("urls") or []
        }
        vulns = [
            Vulnerability(
                id=v.get("id", "unknown"),
                aliases=list(v.get("aliases") or []),
                summary=(v.get("summary") or v.get("details") or "").strip().splitlines()[0][:160]
                if (v.get("summary") or v.get("details")) else "",
                fixed_in=list(v.get("fixed_in") or []),
                withdrawn=bool(v.get("withdrawn")),
            )
            for v in data.get("vulnerabilities") or []
        ]
        return ReleaseDetail(digests=digests, vulnerabilities=[v for v in vulns if not v.withdrawn])

    def provenance(self, name: str, version: str, filename: str) -> dict | None:
        url = f"{self.base}/integrity/{normalize(name)}/{version}/{filename}/provenance"
        status, data = self._get(url)
        return data if status == 200 else None
