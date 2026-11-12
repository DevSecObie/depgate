"""Command-line interface.

Examples:
  depgate requests
  depgate requests==2.32.3 --agent
  depgate -r requirements.txt --agent --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys

from . import __version__
from .checks import ALLOW, BLOCK, FLAG, Decision, evaluate
from .policy import load
from .pypi import PyPIClient

EXIT = {ALLOW: 0, FLAG: 1, BLOCK: 2}
ICON = {"info": "  -", "flag": "  !", "block": "  X"}

REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:==\s*([^\s;#,]+))?")


def parse_spec(spec: str) -> tuple[str, str | None]:
    m = REQ_LINE.match(spec)
    if not m:
        raise ValueError(f"cannot parse package spec: {spec!r}")
    return m.group(1), m.group(2)


def read_requirements(path: str) -> list[tuple[str, str | None]]:
    out = []
    with open(path) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue  # skip blanks, comments, and pip options like -r / -e
            out.append(parse_spec(line))
    return out


def render(d: Decision) -> str:
    head = f"{d.verdict.upper():5}  {d.package}{'==' + d.version if d.version else ''}  [{d.profile}]"
    lines = [head] + [f"{ICON[f.level]} {f.check}: {f.message}" for f in d.findings]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="depgate", description="Dependency admission gate for PyPI packages.")
    ap.add_argument("packages", nargs="*", help="package specs, e.g. requests or requests==2.32.3")
    ap.add_argument("-r", "--requirements", help="check every package in a requirements file")
    ap.add_argument("--agent", action="store_true", help="use the stricter policy for AI-agent-proposed packages")
    ap.add_argument("--policy", help="TOML file with policy overrides")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--version", action="version", version=f"depgate {__version__}")
    args = ap.parse_args(argv)

    specs = [parse_spec(p) for p in args.packages]
    if args.requirements:
        specs += read_requirements(args.requirements)
    if not specs:
        ap.error("give at least one package or -r requirements.txt")

    profile = "agent" if args.agent else "default"
    policy = load(profile, args.policy)
    client = PyPIClient()

    decisions = [evaluate(name, ver, client, policy, profile) for name, ver in specs]

    if args.json:
        print(json.dumps([d.to_dict() for d in decisions], indent=2))
    else:
        print("\n\n".join(render(d) for d in decisions))

    worst = max((EXIT[d.verdict] for d in decisions), default=0)
    return worst


if __name__ == "__main__":
    sys.exit(main())
