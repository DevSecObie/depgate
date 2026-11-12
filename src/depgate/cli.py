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
from .checks import ALLOW, BLOCK, FLAG, Decision, Finding, evaluate
from .hook import Target, emit, hook_response, parse_install_command, read_hook_command
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


def _non_registry(label: str, level: str, message: str, profile: str) -> Decision:
    d = Decision(package=label, version=None, profile=profile)
    d.findings.append(Finding("source", level, message))
    return d


def decide_targets(targets: list[Target], client, policy, profile, verify) -> list[Decision]:
    out: list[Decision] = []
    for t in targets:
        if t.spec:
            name, ver = parse_spec(t.spec)
            out.append(evaluate(name, ver, client, policy, profile, verify=verify))
        elif t.requirements:
            try:
                specs = read_requirements(t.requirements)
            except OSError as e:
                out.append(_non_registry(t.requirements, FLAG, f"Cannot read requirements file: {e}", profile))
                continue
            out += [evaluate(n, v, client, policy, profile, verify=verify) for n, v in specs]
        elif t.custom_index:
            out.append(_non_registry(t.custom_index, FLAG,
                                     "Installs from a non-default package index; depgate only vets PyPI.", profile))
        elif t.direct_source:
            out.append(_non_registry(t.direct_source, FLAG,
                                     "Installs from a URL, VCS repo, or local path, bypassing registry checks.", profile))
    return out


def run_hook(policy_path: str | None, verify: bool, profile: str) -> int:
    """Claude Code PreToolUse hook: deny on block, ask on flag, stay silent on allow."""
    command = read_hook_command(sys.stdin.read())
    if not command:
        return 0
    targets = parse_install_command(command)
    if not targets:
        return 0
    try:
        decisions = decide_targets(targets, PyPIClient(), load(profile, policy_path), profile, verify)
    except Exception as e:  # fail toward a human decision, never silently allow
        emit(hook_response("ask", f"depgate could not evaluate this install ({type(e).__name__}: {e})."))
        return 0
    worst = max((EXIT[d.verdict] for d in decisions), default=0)
    if worst == 0:
        return 0  # allowed: leave the normal permission flow untouched
    reasons = "\n\n".join(render(d) for d in decisions if d.verdict != ALLOW)
    emit(hook_response("deny" if worst == 2 else "ask", f"depgate {'blocked' if worst == 2 else 'flagged'} this install:\n{reasons}"))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="depgate", description="Dependency admission gate for PyPI packages.")
    ap.add_argument("packages", nargs="*", help="package specs, e.g. requests or requests==2.32.3")
    ap.add_argument("-r", "--requirements", help="check every package in a requirements file")
    ap.add_argument("--cmd", help='check the packages a shell command would install, e.g. "pip install foo"')
    ap.add_argument("--hook", action="store_true", help="run as a Claude Code PreToolUse hook (reads JSON on stdin)")
    ap.add_argument("--agent", action="store_true", help="use the stricter policy for AI-agent-proposed packages")
    ap.add_argument("--profile", choices=["default", "agent"], help="explicit policy profile (overrides --agent)")
    ap.add_argument("--policy", help="TOML file with policy overrides")
    ap.add_argument("--no-verify", action="store_true", help="skip cryptographic attestation verification")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--version", action="version", version=f"depgate {__version__}")
    args = ap.parse_args(argv)
    verify = not args.no_verify

    if args.hook:
        # Hook installs come from an agent, so default to the agent profile.
        return run_hook(args.policy, verify, args.profile or "agent")

    profile = args.profile or ("agent" if args.agent else "default")
    targets = [Target(spec=p) for p in args.packages]
    if args.requirements:
        targets.append(Target(requirements=args.requirements))
    if args.cmd:
        found = parse_install_command(args.cmd)
        if not found:
            print("No package installs found in that command.")
            return 0
        targets += found
    if not targets:
        ap.error("give a package, -r requirements.txt, or --cmd")

    policy = load(profile, args.policy)
    decisions = decide_targets(targets, PyPIClient(), policy, profile, verify)

    if args.json:
        print(json.dumps([d.to_dict() for d in decisions], indent=2))
    else:
        print("\n\n".join(render(d) for d in decisions))

    worst = max((EXIT[d.verdict] for d in decisions), default=0)
    return worst


if __name__ == "__main__":
    sys.exit(main())
