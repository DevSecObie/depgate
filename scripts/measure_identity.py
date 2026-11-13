"""Measure how often build-identity checks fire on real, legitimate releases.

For the most-downloaded PyPI packages, take each package's recent signed
releases and replay depgate's comparison release by release: every release
is compared with the signed releases before it. Popular packages' recent
releases are almost all legitimate, so the share that gets flagged is an
upper bound on the false-positive rate.

Usage:
  python scripts/measure_identity.py --top 200 --releases 12 --json out.json

Needs network. Reads PyPI's stored attestations (PyPI verified them at upload);
it does not re-verify signatures.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from depgate import identity as I  # noqa: E402
from depgate.pypi import USER_AGENT, PyPIClient  # noqa: E402

TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"


def top_packages(n: int) -> list[str]:
    req = urllib.request.Request(TOP_URL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as r:
        rows = json.load(r)["rows"]
    return [row["project"] for row in rows[:n]]


def signed_releases(name: str, count: int, history: int):
    """[(version, identity)] oldest first, for the newest `count` releases plus history."""
    client = PyPIClient()
    proj = client.project(name)
    if not proj:
        return []
    releases = sorted((r for r in proj.releases.values() if r.files and r.upload_time and not r.yanked),
                      key=lambda r: r.upload_time)[-(count + history):]
    out = []
    for r in releases:
        wheels = [f for f in r.files if f.packagetype == "bdist_wheel"]
        f = (wheels or r.files)[0]
        prov = client.provenance(proj.name, r.version, f.filename)
        ids = I.from_provenance(prov) if prov else []
        out.append((r.version, ids[0] if ids else None))
    return out


def replay(name: str, count: int, history: int) -> dict:
    try:
        signed = signed_releases(name, count, history)
    except Exception as e:  # network hiccups shouldn't stop the run
        return {"package": name, "error": f"{type(e).__name__}: {e}"}
    compared, flagged, dropped = 0, [], []
    for i in range(1, len(signed)):
        version, cur = signed[i]
        past = [(v, x) for v, x in reversed(signed[:i]) if x][:history]
        if not past:
            continue
        if cur is None:  # signed history, unsigned release
            compared += 1
            judged = I.dropped(version, list(reversed(signed[max(0, i - 10):i])))
            if judged and judged[0] == "flag":
                dropped.append(version)
                flagged.append({"version": version, "fields": ["attestation-dropped"], "levels": ["flag"],
                                "messages": [judged[1]]})
            continue
        changes = [c for c in I.compare(cur, past) if c.level != "info"]
        compared += 1
        if changes:
            flagged.append({"version": version, "fields": [c.field for c in changes],
                            "levels": [c.level for c in changes],
                            "messages": [c.message for c in changes]})
    return {"package": name, "signed": sum(1 for _, x in signed if x), "compared": compared,
            "flagged": flagged, "dropped": dropped}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=200, help="how many top packages to scan")
    ap.add_argument("--releases", type=int, default=12, help="recent releases per package to replay")
    ap.add_argument("--history", type=int, default=5, help="earlier signed releases to compare with")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--json", help="write full results here")
    args = ap.parse_args()

    names = top_packages(args.top)
    with ThreadPoolExecutor(args.workers) as pool:
        results = list(pool.map(lambda n: replay(n, args.releases, args.history), names))

    ok = [r for r in results if "error" not in r]
    signed_pkgs = [r for r in ok if r["signed"]]
    compared = sum(r["compared"] for r in ok)
    flagged = [(r["package"], f) for r in ok for f in r["flagged"]]
    blocks = [x for x in flagged if "block" in x[1]["levels"]]
    fields = Counter(fld for _, f in flagged for fld in f["fields"])
    pkgs_flagged = {p for p, _ in flagged}

    summary = {
        "packages_scanned": len(names),
        "errors": len(results) - len(ok),
        "packages_with_attestations": len(signed_pkgs),
        "releases_compared": compared,
        "releases_flagged": len(flagged),
        "releases_blocked": len(blocks),
        "flag_rate": round(len(flagged) / compared, 4) if compared else None,
        "packages_with_any_flag": len(pkgs_flagged),
        "by_field": dict(fields.most_common()),
    }
    print(json.dumps(summary, indent=2))
    for pkg, f in flagged[:40]:
        print(f"- {pkg}=={f['version']}: {'; '.join(f['messages'])[:220]}")
    if args.json:
        Path(args.json).write_text(json.dumps({"summary": summary, "results": results}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
