"""Offline tests: a fake fetcher stands in for PyPI."""

import unittest
from datetime import datetime, timedelta, timezone

from depgate import verify as verify_mod
from depgate.checks import ALLOW, BLOCK, FLAG, evaluate, lookalikes
from depgate.cli import parse_spec
from depgate.hook import parse_install_command, read_hook_command
from depgate.policy import AGENT, DEFAULT
from depgate.popular import POPULAR_SET
from depgate.pypi import PyPIClient

NOW = datetime(2026, 11, 12, tzinfo=timezone.utc)
POP = frozenset(POPULAR_SET)


def iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat()


def file(name, version, days_ago, kind="bdist_wheel", yanked=False):
    ext = "whl" if kind == "bdist_wheel" else "tar.gz"
    return {
        "filename": f"{name}-{version}.{ext}",
        "packagetype": kind,
        "upload_time_iso_8601": iso(days_ago),
        "yanked": yanked,
    }


def project(name, releases, urls=None):
    """releases: {version: [file dicts]}; latest = last key."""
    return {
        "info": {
            "name": name,
            "version": list(releases)[-1],
            "summary": "",
            "project_urls": urls if urls is not None else {"Source": "https://github.com/x/y"},
        },
        "releases": releases,
    }


class FakePyPI:
    def __init__(self, projects=None, attested=None, vulns=None, publisher_repo="x/y"):
        self.projects = projects or {}
        self.attested = attested or set()  # filenames with provenance
        self.vulns = vulns or {}           # (name, version) -> list of vuln dicts
        self.publisher_repo = publisher_repo

    def __call__(self, url):
        if "/integrity/" in url:
            fname = url.rstrip("/").split("/")[-2]
            if fname in self.attested:
                return 200, {"attestation_bundles": [
                    {"publisher": {"kind": "GitHub", "repository": self.publisher_repo}}]}
            return 404, None
        parts = url.split("/pypi/")[1].split("/")
        name = parts[0]
        if name not in self.projects:
            return 404, None
        if len(parts) == 3:  # /pypi/<name>/<version>/json
            version = parts[1]
            files = self.projects[name]["releases"].get(version, [])
            return 200, {
                "urls": [{"filename": f["filename"], "digests": {"sha256": "ab" * 32}} for f in files],
                "vulnerabilities": self.vulns.get((name, version), []),
            }
        return 200, self.projects[name]


# Stand-in for real Sigstore verification so tests run offline and deterministically.
TAMPERED: set[str] = set()


def fake_verify(filename, sha256, provenance, state):
    pub = provenance["attestation_bundles"][0]["publisher"]
    desc = verify_mod.describe_publisher(pub)
    if filename in TAMPERED:
        return [verify_mod.FileResult(filename, False, desc, error="VerificationError: digest mismatch")]
    return [verify_mod.FileResult(filename, True, desc)]


def setUpModule():
    verify_mod.AVAILABLE = True
    verify_mod.verify_provenance = fake_verify


def run(fake, name, version=None, agent=False):
    client = PyPIClient(fetch=fake)
    return evaluate(name, version, client, AGENT if agent else DEFAULT,
                    "agent" if agent else "default", now=NOW)


MATURE = project("goodpkg", {
    "1.0": [file("goodpkg", "1.0", 900)],
    "1.1": [file("goodpkg", "1.1", 600)],
    "2.0": [file("goodpkg", "2.0", 100)],
})


class TestVerdicts(unittest.TestCase):
    def test_missing_package_blocks(self):
        d = run(FakePyPI(), "nonexistent-thing")
        self.assertEqual(d.verdict, BLOCK)

    def test_missing_typo_suggests_real_name(self):
        d = run(FakePyPI(), "reqeusts", agent=True)
        self.assertEqual(d.verdict, BLOCK)
        self.assertIn("requests", d.findings[0].message)
        self.assertIn("hallucination", d.findings[0].message)

    def test_mature_attested_package_allows(self):
        fake = FakePyPI({"goodpkg": MATURE}, attested={"goodpkg-2.0.whl"})
        d = run(fake, "goodpkg")
        self.assertEqual(d.verdict, ALLOW)

    def test_mature_unattested_flags_only_in_agent_mode(self):
        fake = FakePyPI({"goodpkg": MATURE})
        self.assertEqual(run(fake, "goodpkg").verdict, ALLOW)
        self.assertEqual(run(fake, "goodpkg", agent=True).verdict, FLAG)

    def test_brand_new_package(self):
        fake = FakePyPI({"freshpkg": project("freshpkg", {"0.1": [file("freshpkg", "0.1", 2)]})})
        self.assertEqual(run(fake, "freshpkg").verdict, FLAG)
        self.assertEqual(run(fake, "freshpkg", agent=True).verdict, BLOCK)

    def test_unknown_version_blocks(self):
        fake = FakePyPI({"goodpkg": MATURE})
        self.assertEqual(run(fake, "goodpkg", "9.9").verdict, BLOCK)

    def test_yanked_version_blocks(self):
        p = project("goodpkg", {
            "1.0": [file("goodpkg", "1.0", 900)],
            "1.1": [file("goodpkg", "1.1", 600)],
            "2.0": [file("goodpkg", "2.0", 100, yanked=True)],
        })
        self.assertEqual(run(FakePyPI({"goodpkg": p}), "goodpkg", "2.0").verdict, BLOCK)

    def test_sdist_only_flags(self):
        p = project("oldpkg", {
            "1.0": [file("oldpkg", "1.0", 900, kind="sdist")],
            "1.1": [file("oldpkg", "1.1", 800, kind="sdist")],
            "1.2": [file("oldpkg", "1.2", 700, kind="sdist")],
        })
        d = run(FakePyPI({"oldpkg": p}), "oldpkg")
        self.assertEqual(d.verdict, FLAG)
        self.assertIn("install-code", [f.check for f in d.findings])

    def test_existing_typosquat(self):
        p = project("reqests", {
            "1.0": [file("reqests", "1.0", 900)],
            "1.1": [file("reqests", "1.1", 800)],
            "1.2": [file("reqests", "1.2", 700)],
        })
        fake = FakePyPI({"reqests": p}, attested={"reqests-1.2.whl"})
        self.assertEqual(run(fake, "reqests").verdict, FLAG)
        self.assertEqual(run(fake, "reqests", agent=True).verdict, BLOCK)


class TestLookalikes(unittest.TestCase):
    def test_popular_name_is_not_its_own_lookalike(self):
        self.assertEqual(lookalikes("requests", POP, 2), [])

    def test_separator_variants_are_the_same_package(self):
        self.assertEqual(lookalikes("Python_DateUtil", POP, 2), [])

    def test_affixes_both_directions(self):
        self.assertIn("requests", lookalikes("requests-python", POP, 1))
        self.assertIn("python-dateutil", lookalikes("dateutil", POP, 1))

    def test_swap_is_distance_one(self):
        self.assertIn("requests", lookalikes("reqeusts", POP, 1))


class TestSpecParsing(unittest.TestCase):
    def test_specs(self):
        self.assertEqual(parse_spec("requests==2.32.3"), ("requests", "2.32.3"))
        self.assertEqual(parse_spec("requests"), ("requests", None))
        self.assertEqual(parse_spec("uvicorn[standard]==0.30.0"), ("uvicorn", "0.30.0"))
        self.assertEqual(parse_spec("flask>=3.0"), ("flask", None))


class TestVerificationAndVulns(unittest.TestCase):
    def tearDown(self):
        TAMPERED.clear()

    def test_verified_attestation_allows(self):
        fake = FakePyPI({"goodpkg": MATURE}, attested={"goodpkg-2.0.whl"})
        d = run(fake, "goodpkg")  # agent mode would flag the short release history
        self.assertEqual(d.verdict, ALLOW)
        self.assertIn("verified", " ".join(f.message for f in d.findings))

    def test_failed_verification_blocks(self):
        TAMPERED.add("goodpkg-2.0.whl")
        fake = FakePyPI({"goodpkg": MATURE}, attested={"goodpkg-2.0.whl"})
        self.assertEqual(run(fake, "goodpkg").verdict, BLOCK)

    def test_publisher_from_other_owner_flags(self):
        fake = FakePyPI({"goodpkg": MATURE}, attested={"goodpkg-2.0.whl"}, publisher_repo="attacker/y")
        d = run(fake, "goodpkg")
        self.assertEqual(d.verdict, FLAG)
        self.assertIn("different owner", " ".join(f.message for f in d.findings))

    def test_publisher_same_org_other_repo_is_info(self):
        fake = FakePyPI({"goodpkg": MATURE}, attested={"goodpkg-2.0.whl"}, publisher_repo="x/y-release")
        self.assertEqual(run(fake, "goodpkg").verdict, ALLOW)

    def test_vulnerabilities_flag_or_block_and_dedupe(self):
        vulns = {("goodpkg", "2.0"): [
            {"id": "PYSEC-1", "aliases": ["CVE-2026-0001"], "fixed_in": ["2.1"]},
            {"id": "GHSA-aaaa", "aliases": ["CVE-2026-0001"], "fixed_in": ["2.1"]},
            {"id": "PYSEC-2", "aliases": [], "fixed_in": [], "withdrawn": "2026-01-01"},
        ]}
        fake = FakePyPI({"goodpkg": MATURE}, attested={"goodpkg-2.0.whl"}, vulns=vulns)
        d = run(fake, "goodpkg")
        self.assertEqual(d.verdict, FLAG)
        msg = [f.message for f in d.findings if f.check == "vulnerabilities"][0]
        self.assertTrue(msg.startswith("1 known"))  # duplicate collapsed, withdrawn dropped
        self.assertEqual(run(fake, "goodpkg", agent=True).verdict, BLOCK)


class TestInstallCommandParsing(unittest.TestCase):
    def specs(self, cmd):
        return [t.spec for t in parse_install_command(cmd) if t.spec]

    def test_common_installers(self):
        self.assertEqual(self.specs("pip install requests flask==3.0"), ["requests", "flask==3.0"])
        self.assertEqual(self.specs("python3.12 -m pip install -U --user rich"), ["rich"])
        self.assertEqual(self.specs("uv add httpx"), ["httpx"])
        self.assertEqual(self.specs("uv pip install pydantic"), ["pydantic"])
        self.assertEqual(self.specs("poetry add numpy"), ["numpy"])
        self.assertEqual(self.specs("sudo /usr/bin/pip3 install boto3"), ["boto3"])

    def test_chained_commands(self):
        self.assertEqual(self.specs("cd app && pip install a; echo done || pip install b"), ["a", "b"])

    def test_ignores_non_installs(self):
        self.assertEqual(parse_install_command("pip list && pip show requests && ls"), [])

    def test_special_sources(self):
        t = parse_install_command("pip install -r reqs.txt -i https://mirror/simple git+https://x/y.git ./local")
        self.assertEqual(t[0].requirements, "reqs.txt")
        self.assertEqual(t[1].custom_index, "https://mirror/simple")
        self.assertEqual([x.direct_source for x in t[2:]], ["git+https://x/y.git", "./local"])

    def test_option_values_are_not_packages(self):
        self.assertEqual(self.specs("pip install --target /tmp/x -c constraints.txt six"), ["six"])

    def test_npm_installers(self):
        specs = self.specs("npm i -D @scope/pkg@1.2.3 left-pad && pnpm add --filter web zod; yarn add react@^18")
        self.assertEqual(specs, ["npm:@scope/pkg@1.2.3", "npm:left-pad", "npm:zod", "npm:react@^18"])
        self.assertEqual(parse_install_command("npm install"), [])  # lockfile install: nothing named
        t = parse_install_command("npm install user/repo ./local.tgz --registry https://r.example")
        self.assertEqual([x.direct_source for x in t[:2]], ["user/repo", "./local.tgz"])
        self.assertEqual(t[2].custom_index, "https://r.example")

    def test_hook_event_reading(self):
        self.assertEqual(read_hook_command('{"tool_name":"Bash","tool_input":{"command":"pip install x"}}'),
                         "pip install x")
        self.assertIsNone(read_hook_command('{"tool_name":"Edit","tool_input":{}}'))
        self.assertIsNone(read_hook_command("not json"))


if __name__ == "__main__":
    unittest.main()
