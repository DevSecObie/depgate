"""Gate package installs that an AI coding agent tries to run.

Two entry points:

  depgate --cmd "pip install foo bar"
      Check the packages a shell command would install.

  depgate --hook
      Claude Code PreToolUse hook. Reads the hook event JSON on stdin,
      and for Bash commands that install packages:
        block -> deny the command, with depgate's reasons
        flag  -> ask the human to approve it
        allow -> let it run
      Commands that don't install anything pass through untouched.

Agent-run installs always use the stricter "agent" profile unless overridden.
"""

from __future__ import annotations

import json
import re
import shlex
import sys
from dataclasses import dataclass

# Installer invocations, as token prefixes after normalization.
INSTALLERS = [
    ("pip", "install"),
    ("pip3", "install"),
    ("python", "-m", "pip", "install"),
    ("python3", "-m", "pip", "install"),
    ("uv", "pip", "install"),
    ("uv", "add"),
    ("poetry", "add"),
    ("pipx", "install"),
]

# npm-ecosystem installers. depgate checks only build identity for these.
NPM_INSTALLERS = [
    ("npm", "install"), ("npm", "i"), ("npm", "add"), ("npm", "isntall"),
    ("pnpm", "add"), ("pnpm", "install"), ("pnpm", "i"),
    ("yarn", "add"), ("bun", "add"), ("bun", "install"), ("bun", "i"),
]
NPM_OPTS_WITH_VALUE = {"--prefix", "-w", "--workspace", "--tag", "--filter", "-C", "--dir", "--cwd"}

# pip/uv options that consume the next token.
OPTS_WITH_VALUE = {
    "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-c", "--constraint",
    "-t", "--target", "--prefix", "--root", "--python", "-p", "--src", "--trusted-host",
    "--platform", "--python-version", "--implementation", "--abi", "--group", "--extra",
    "--source", "-G",
}
SEPARATORS = re.compile(r"\s*(?:&&|\|\||;|\|)\s*")


@dataclass
class Target:
    spec: str | None = None          # a registry package spec, e.g. "requests==2.32.3"
    requirements: str | None = None  # a -r file
    custom_index: str | None = None  # non-default index in use
    direct_source: str | None = None # URL, VCS, or local path install


def _split_commands(command: str) -> list[list[str]]:
    out = []
    for part in SEPARATORS.split(command):
        part = part.strip()
        if not part:
            continue
        try:
            tokens = shlex.split(part)
        except ValueError:
            tokens = part.split()
        # Drop leading env assignments and sudo.
        while tokens and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]) or tokens[0] == "sudo"):
            tokens = tokens[1:]
        if tokens:
            tokens[0] = tokens[0].rsplit("/", 1)[-1]  # /usr/bin/pip3 -> pip3
            m = re.fullmatch(r"(python3?|pip3?)(\.\d+)?", tokens[0])
            if m:
                tokens[0] = m.group(1)  # python3.12 -> python3, pip3.12 -> pip3
            out.append(tokens)
    return out


def _npm_targets(args: list[str]) -> list[Target]:
    targets: list[Target] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--registry" and i + 1 < len(args):
            targets.append(Target(custom_index=args[i + 1]))
            i += 2
            continue
        if a.startswith("--registry="):
            targets.append(Target(custom_index=a.split("=", 1)[1]))
        elif a in NPM_OPTS_WITH_VALUE:
            i += 2
            continue
        elif a.startswith("-"):
            pass
        elif ("://" in a or a.startswith(("git+", "git:", "github:", "file:", "link:", "npm:", ".", "/", "~"))
              or a.endswith((".tgz", ".tar.gz")) or ("/" in a and not a.startswith("@"))):
            targets.append(Target(direct_source=a))  # URL, path, alias or user/repo shorthand
        else:
            targets.append(Target(spec="npm:" + a))
        i += 1
    return targets


def parse_install_command(command: str) -> list[Target]:
    """Install targets in a shell command. npm-ecosystem specs come back as 'npm:<spec>'.

    A bare `npm install` / `pnpm install` (install from the lockfile) names no
    packages, so there is nothing to check here.
    """
    targets: list[Target] = []
    for tokens in _split_commands(command):
        npm_args = None
        for prefix in NPM_INSTALLERS:
            if [t.lower() for t in tokens[:len(prefix)]] == list(prefix):
                npm_args = tokens[len(prefix):]
                break
        if npm_args is not None:
            targets += _npm_targets(npm_args)
            continue
        args = None
        for prefix in INSTALLERS:
            n = len(prefix)
            if [t.lower() for t in tokens[:n]] == list(prefix):
                args = tokens[n:]
                break
        if args is None:
            continue
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("-r", "--requirement"):
                if i + 1 < len(args):
                    targets.append(Target(requirements=args[i + 1]))
                i += 2
                continue
            if a.startswith("--requirement="):
                targets.append(Target(requirements=a.split("=", 1)[1]))
            elif a in ("-i", "--index-url", "--extra-index-url") and i + 1 < len(args):
                targets.append(Target(custom_index=args[i + 1]))
                i += 2
                continue
            elif a.startswith(("--index-url=", "--extra-index-url=")):
                targets.append(Target(custom_index=a.split("=", 1)[1]))
            elif a in ("-e", "--editable"):
                if i + 1 < len(args):
                    targets.append(Target(direct_source=args[i + 1]))
                i += 2
                continue
            elif a in OPTS_WITH_VALUE:
                i += 2
                continue
            elif a.startswith("-"):
                pass  # flag like -U, --user, --break-system-packages
            elif "://" in a or a.startswith(("git+", ".", "/", "~")) or " @ " in a or a.endswith((".whl", ".tar.gz", ".zip")):
                targets.append(Target(direct_source=a))
            else:
                targets.append(Target(spec=a))
            i += 1
    return targets


def hook_response(decision: str, reason: str) -> dict:
    """Claude Code PreToolUse hook output."""
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,  # "allow" | "deny" | "ask"
            "permissionDecisionReason": reason,
        }
    }


def read_hook_command(stdin_text: str) -> str | None:
    try:
        event = json.loads(stdin_text or "{}")
    except json.JSONDecodeError:
        return None
    if event.get("tool_name") != "Bash":
        return None
    return (event.get("tool_input") or {}).get("command")


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()
