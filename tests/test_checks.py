"""Offline tests: a fake fetcher stands in for PyPI."""

import unittest
from datetime import datetime, timedelta, timezone

from depgate.checks import ALLOW, BLOCK, FLAG, evaluate, lookalikes
from depgate.cli import parse_spec
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
    def __init__(self, projects=None, attested=None):
        self.projects = projects or {}
        self.attested = attested or set()  # filenames with provenance

    def __call__(self, url):
        if "/integrity/" in url:
            fname = url.rstrip("/").split("/")[-2]
            if fname in self.attested:
                return 200, {"attestation_bundles": [
                    {"publisher": {"kind": "GitHub", "repository": "org/repo"}}]}
            return 404, None
        name = url.split("/pypi/")[1].split("/")[0]
        if name in self.projects:
            return 200, self.projects[name]
        return 404, None


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


if __name__ == "__main__":
    unittest.main()
