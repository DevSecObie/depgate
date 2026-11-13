"""Build identity: certificate parsing, comparison, incident replays, pins.

Replays use real signing certificates from two incidents (see the README in
each tests/fixtures/incidents/ folder). Everything runs offline.
"""

import base64
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from depgate import identity as I
from depgate import pins as pins_mod
from depgate import npm as npm_mod
from depgate.checks import ALLOW, BLOCK, FLAG, INFO, evaluate, evaluate_npm
from depgate.policy import AGENT, DEFAULT
from depgate.pypi import PyPIClient

from test_checks import NOW, file, project  # noqa: E402  (shared helpers)

FIX = Path(__file__).parent / "fixtures"
REDHAT = FIX / "incidents" / "redhat-npm-2026-06"
ULTRA = FIX / "incidents" / "ultralytics-pypi-2024-12"
AXIOS = FIX / "incidents" / "axios-npm-2026-03"


def cert_b64(path: Path) -> str:
    return path.read_text().strip()


def ident(path: Path) -> I.BuildIdentity:
    return I.from_certificate(base64.b64decode(cert_b64(path)))


def history(folder: Path, versions: list[str]) -> list[tuple[str, I.BuildIdentity]]:
    """Newest first, as compare() expects."""
    return [(v, ident(folder / f"{v}.cert.b64")) for v in reversed(versions)]


class TestCertificateParsing(unittest.TestCase):
    def test_real_pypi_attestation(self):
        prov = json.loads((FIX / "sigstore-4.5.1.provenance.json").read_text())
        [i] = I.from_provenance(prov)
        self.assertEqual(i.repo, "sigstore/sigstore-python")
        self.assertEqual(i.source_repo_ref, "refs/tags/v4.5.1")
        self.assertEqual(i.ref_kind, "tag")
        self.assertEqual(i.build_trigger, "release")
        self.assertEqual(i.runner_environment, "github-hosted")
        self.assertEqual(i.source_repo_id, "447691086")
        self.assertEqual(i.source_repo_owner_id, "71096353")
        self.assertEqual(i.workflow, "sigstore/sigstore-python/.github/workflows/release.yml")
        self.assertEqual(i.source_repo_visibility, "public")
        self.assertTrue(i.run_invocation_uri.startswith("https://github.com/sigstore/sigstore-python/actions/runs/"))

    def test_garbage_certificate_is_skipped(self):
        prov = {"attestation_bundles": [{"attestations": [
            {"verification_material": {"certificate": base64.b64encode(b"\x30\x05junk").decode()}}]}]}
        self.assertEqual(I.from_provenance(prov), [])

    def test_missing_fields_are_empty(self):
        self.assertEqual(I.from_provenance({}), [])


class TestIncidentReplays(unittest.TestCase):
    """Real certificates. These are the numbers to quote, good and bad."""

    def test_redhat_throwaway_branch_is_flagged(self):
        past = history(REDHAT, ["3.4.2", "3.5.0", "3.5.1", "3.5.2", "3.6.0"])
        bad = ident(REDHAT / "3.6.1-malicious.cert.b64")
        changes = I.compare(bad, past)
        self.assertEqual([c.field for c in changes], ["ref"])
        self.assertEqual(changes[0].level, "flag")
        self.assertIn("refs/heads/oidc-61fff775", changes[0].message)
        self.assertIn("refs/heads/master", changes[0].message)

    def test_redhat_legitimate_releases_are_quiet(self):
        versions = ["3.4.2", "3.5.0", "3.5.1", "3.5.2", "3.6.0"]
        for n in range(1, len(versions)):
            cur = ident(REDHAT / f"{versions[n]}.cert.b64")
            self.assertEqual(I.compare(cur, history(REDHAT, versions[:n])), [], versions[n])

    def test_ultralytics_cache_poisoning_is_not_caught(self):
        """Documented limit: the attack ran inside the normal release pipeline."""
        past = history(ULTRA, ["8.3.38", "8.3.39", "8.3.40"])
        self.assertEqual(I.compare(ident(ULTRA / "rekor-153589716.cert.b64"), past), [])

    def test_ultralytics_token_release_is_flagged(self):
        """Second round (8.3.45, 8.3.46): leftover API token, no attestation, after signed releases."""
        earlier = [("8.3.43", ident(ULTRA / "8.3.43.cert.b64"))] + history(ULTRA, ["8.3.38", "8.3.39", "8.3.40"])
        level, msg = I.dropped("8.3.45", earlier)
        self.assertEqual(level, "flag")
        self.assertIn("ultralytics/ultralytics", msg)

    def test_ultralytics_cleanup_release_is_a_false_positive(self):
        """Documented false positive: a legitimate release from a personal branch, run by hand."""
        past = history(ULTRA, ["8.3.38", "8.3.39", "8.3.40"])
        changes = I.compare(ident(ULTRA / "8.3.43.cert.b64"), past)
        self.assertEqual({c.field for c in changes}, {"ref", "trigger"})
        self.assertTrue(all(c.level == "flag" for c in changes))


BASE = I.BuildIdentity(
    source_repo_uri="https://github.com/acme/lib", source_repo_id="100", source_repo_owner_id="7",
    source_repo_ref="refs/tags/v1.0", build_trigger="push", runner_environment="github-hosted",
    build_config_uri="https://github.com/acme/lib/.github/workflows/release.yml@refs/tags/v1.0",
    build_signer_uri="https://github.com/acme/lib/.github/workflows/release.yml@refs/tags/v1.0",
    deployment_environment="pypi", source_repo_visibility="public",
)


class TestCompare(unittest.TestCase):
    def changes(self, **kw):
        return I.compare(replace(BASE, **kw), [("1.0", BASE)])

    def test_per_version_branches_are_one_family(self):
        past = [("9.1.1", replace(BASE, source_repo_ref="refs/heads/release-9.1.1"))]
        self.assertEqual(I.compare(replace(BASE, source_repo_ref="refs/heads/release-9.2.0"), past), [])
        [c] = I.compare(replace(BASE, source_repo_ref="refs/heads/oidc-61fff775"), past)
        self.assertEqual(c.field, "ref")

    def test_new_tag_is_normal(self):
        self.assertEqual(self.changes(source_repo_ref="refs/tags/v1.1"), [])

    def test_repo_recreated_under_same_name_blocks(self):
        [c] = self.changes(source_repo_id="999")
        self.assertEqual((c.field, c.level), ("repo-id", "block"))

    def test_rename_with_same_id_is_info(self):
        [c] = self.changes(source_repo_uri="https://github.com/acme/lib2")
        self.assertEqual((c.field, c.level), ("repo", "info"))

    def test_owner_change_flags(self):
        self.assertIn(("owner-id", "flag"), [(c.field, c.level) for c in self.changes(source_repo_owner_id="8")])

    def test_self_hosted_runner_flags(self):
        [c] = self.changes(runner_environment="self-hosted")
        self.assertEqual(c.field, "runner")
        self.assertIn("self-hosted", c.message)

    def test_environment_dropped_flags(self):
        [c] = self.changes(deployment_environment="")
        self.assertIn("No deployment environment", c.message)

    def test_other_workflow_flags(self):
        wf = "https://github.com/acme/lib/.github/workflows/ci.yml@refs/heads/x"
        fields = {c.field for c in self.changes(build_config_uri=wf, build_signer_uri=wf)}
        self.assertEqual(fields, {"workflow", "signer"})

    def test_two_unsigned_in_a_row_still_flag(self):
        S = BASE
        level, msg = I.dropped("8.3.46", [("8.3.45", None), ("8.3.44", S), ("8.3.43", S)])
        self.assertEqual(level, "flag")
        self.assertIn("1 unsigned release(s) since 8.3.44", msg)
        self.assertEqual(I.dropped("8.3.47", [("8.3.46", None), ("8.3.45", None), ("8.3.44", S)])[0], "flag")
        self.assertEqual(I.dropped("8.3.48", [("8.3.47", None), ("8.3.46", None), ("8.3.45", None),
                                              ("8.3.44", S)])[0], "info")

    def test_parallel_lines_look_deeper(self):
        """Signed 2.0.x release beyond the short window must still be found."""
        proj_releases = {}
        order = [("2.0.52", True), ("2.1.3", True), ("2.1.4", True), ("2.1.5", True), ("2.1.6", True),
                 ("2.0.53", False), ("2.1.7", True), ("2.0.54", False)]
        for n, (v, _) in enumerate(order):
            proj_releases[v] = [file("pkg", v, 400 - 10 * n)]
        proj = project("pkg", proj_releases, {"Source": "https://github.com/RedHatInsights/frontend-components"})
        certs = {f"pkg-{v}.whl": cert_b64(REDHAT / "3.6.0.cert.b64") for v, signed in order if signed}
        d = evaluate("pkg", "2.0.54", PyPIClient(fetch=CertPyPI(proj, certs)), DEFAULT, "default", now=NOW)
        [f] = by_check(d, "attestation-dropped")
        self.assertEqual(f.level, FLAG)

    def test_dropped_rules(self):
        S = BASE
        self.assertIsNone(I.dropped("1.3", [("1.2", None), ("1.1", None)]))  # never signed
        self.assertEqual(I.dropped("1.3", [("1.2", S), ("1.1", S)])[0], "flag")  # first drop
        level, msg = I.dropped("1.6", [("1.5", None), ("1.4", None), ("1.3", None), ("1.2", S)])  # stopped
        self.assertEqual(level, "info")
        self.assertIn("stopped signing after 1.2", msg)
        level, msg = I.dropped("2.0.54", [("2.1.7", S), ("2.0.53", None), ("2.1.6", S)])  # unsigned line
        self.assertEqual(level, "info")
        self.assertIn("2.0.x line has never been signed", msg)
        self.assertEqual(I.dropped("2.1.8", [("2.0.53", None), ("2.1.7", S)])[0], "flag")  # signed line drops

    def test_fields_absent_in_history_are_not_compared(self):
        past = [("1.0", replace(BASE, deployment_environment=""))]
        self.assertEqual(I.compare(replace(BASE, deployment_environment="pypi"), past), [])


# ---------- through evaluate(), with a fake PyPI ----------

def redhat_project():
    versions = ["3.4.2", "3.5.0", "3.5.1", "3.5.2", "3.6.0", "3.6.1"]
    releases = {v: [file("rhtypes", v, 400 - 60 * n)] for n, v in enumerate(versions)}
    certs = {f"rhtypes-{v}.whl": cert_b64(REDHAT / f"{v}.cert.b64") for v in versions[:-1]}
    certs["rhtypes-3.6.1.whl"] = cert_b64(REDHAT / "3.6.1-malicious.cert.b64")
    urls = {"Source": "https://github.com/RedHatInsights/frontend-components"}
    return project("rhtypes", releases, urls), certs


class CertPyPI:
    """Fake PyPI whose provenance carries real certificates."""

    def __init__(self, proj, certs):
        self.proj, self.certs = proj, certs

    def __call__(self, url):
        if "/integrity/" in url:
            fname = url.rstrip("/").split("/")[-2]
            if fname not in self.certs:
                return 404, None
            return 200, {"attestation_bundles": [{
                "publisher": {"kind": "GitHub", "repository": "RedHatInsights/frontend-components",
                              "workflow": "ci.yaml", "environment": None},
                "attestations": [{"verification_material": {"certificate": self.certs[fname]}}]}]}
        parts = url.split("/pypi/")[1].split("/")
        if parts[0] != self.proj["info"]["name"]:
            return 404, None
        if len(parts) == 3:
            files = self.proj["releases"].get(parts[1], [])
            return 200, {"urls": [{"filename": f["filename"], "digests": {"sha256": "ab" * 32}} for f in files],
                         "vulnerabilities": []}
        return 200, self.proj


def check(version, profile=DEFAULT, **kw):
    proj, certs = redhat_project()
    return evaluate("rhtypes", version, PyPIClient(fetch=CertPyPI(proj, certs)), profile,
                    "agent" if profile is AGENT else "default", now=NOW, **kw)


def by_check(d, name):
    return [f for f in d.findings if f.check == name]


class TestEvaluate(unittest.TestCase):
    def test_malicious_release_flags(self):
        d = check("3.6.1")
        self.assertEqual(d.verdict, FLAG)
        [f] = [f for f in by_check(d, "build-identity") if f.level != INFO]
        self.assertIn("oidc-61fff775", f.message)
        self.assertIn("actions/runs/", f.message)  # links the build run
        self.assertEqual(d.identity["source_repo_ref"], "refs/heads/oidc-61fff775")

    def test_legitimate_release_matches_history(self):
        d = check("3.6.0")
        self.assertEqual(d.verdict, ALLOW)
        [f] = by_check(d, "build-identity")
        self.assertIn("matches the 4 earlier signed release(s)", f.message)

    def test_first_signed_release_has_nothing_to_compare(self):
        [f] = by_check(check("3.4.2"), "build-identity")
        self.assertIn("No earlier signed releases", f.message)

    def test_identity_only_skips_other_checks(self):
        # A policy wanting a longer release history makes the full check flag.
        picky = replace(DEFAULT, min_releases=10)
        full = check("3.6.0", picky)
        only = check("3.6.0", picky, identity_only=True)
        self.assertEqual(full.verdict, FLAG)
        self.assertEqual(only.verdict, ALLOW)
        self.assertEqual({f.check for f in only.findings}, {"provenance", "build-identity"})

    def test_policy_can_block_identity_changes(self):
        strict = replace(DEFAULT, identity_change_action="block")
        self.assertEqual(check("3.6.1", strict).verdict, BLOCK)

    def test_pins(self):
        legit = check("3.6.0")
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "pins.json")
            self.assertEqual(pins_mod.update(path, [legit]), (["rhtypes==3.6.0"], []))
            # A blocked release is never pinned...
            import test_checks
            test_checks.TAMPERED.add("rhtypes-3.6.1.whl")
            try:
                blocked = check("3.6.1")
            finally:
                test_checks.TAMPERED.clear()
            self.assertEqual(blocked.verdict, BLOCK)
            self.assertEqual(pins_mod.update(path, [blocked]), ([], []))  # failed signature: no identity
            blocked.identity = {"source_repo_uri": "x"}
            self.assertEqual(pins_mod.update(path, [blocked]), ([], ["rhtypes==3.6.1"]))
            # ...but a reviewed, flagged change can be accepted (re-pinned).
            flagged = check("3.6.1")
            self.assertEqual(flagged.verdict, FLAG)
            self.assertEqual(pins_mod.update(path, [flagged]), (["rhtypes==3.6.1"], []))
            pins_mod.update(path, [legit])
            saved = json.loads(Path(path).read_text())["packages"]["rhtypes"][0]
            self.assertNotIn("run_invocation_uri", saved)  # per-run fields aren't pinned
            pins = pins_mod.load(path)
        d = check("3.6.1", pins=pins)
        self.assertIn("oidc-61fff775", by_check(d, "identity-pin")[0].message)
        self.assertEqual(by_check(check("3.6.0", pins=pins), "identity-pin")[0].level, INFO)

    def test_failed_signature_publisher_is_not_emitted(self):
        import test_checks
        test_checks.TAMPERED.add("rhtypes-3.6.0.whl")
        try:
            d = check("3.6.0")
        finally:
            test_checks.TAMPERED.clear()
        self.assertEqual(d.verdict, BLOCK)
        self.assertEqual(d.attestation_identities, [])
        self.assertIsNone(d.identity)
        self.assertEqual(pins_mod.pep751([d]), "")

    def test_pep751_output(self):
        out = pins_mod.pep751([check("3.6.0")])
        self.assertIn("[[packages.attestation-identities]]", out)
        self.assertIn('repository = "RedHatInsights/frontend-components"', out)
        self.assertIn('workflow = "ci.yaml"', out)
        self.assertNotIn("environment", out)  # None values are dropped


    def test_dropped_attestation_flags(self):
        """Ultralytics 8.3.45/8.3.46 shape: signed history, then a release with no attestation."""
        proj, certs = redhat_project()
        del certs["rhtypes-3.6.1.whl"]
        d = evaluate("rhtypes", "3.6.1", PyPIClient(fetch=CertPyPI(proj, certs)), DEFAULT, "default", now=NOW)
        self.assertEqual(d.verdict, FLAG)
        [f] = by_check(d, "attestation-dropped")
        self.assertIn("3.6.0", f.message)

    def test_never_signed_package_is_not_a_drop(self):
        proj, _ = redhat_project()
        d = evaluate("rhtypes", "3.6.1", PyPIClient(fetch=CertPyPI(proj, {})), DEFAULT, "default", now=NOW)
        self.assertEqual(by_check(d, "attestation-dropped"), [])


# ---------- npm ----------

class FakeNpm:
    """Stands in for npm_mod.NpmClient. versions: [(version, iso time, cert path or None)]."""

    def __init__(self, name, versions):
        self.name = name
        self.certs = {v: c for v, _, c in versions}
        self.pkg = npm_mod.NpmPackage(name, versions[-1][0], {
            v: npm_mod.NpmVersion(v, npm_mod._time(t), "", c is not None) for v, t, c in versions})

    def package(self, name):
        return self.pkg if name == self.name else None

    def provenance_bundle(self, name, version):
        c = self.certs.get(version)
        return {"verificationMaterial": {"certificate": {"rawBytes": cert_b64(c)}}} if c else None


def npm_check(fake, name, version, **kw):
    return evaluate_npm(name, version, fake, DEFAULT, verify=False, **kw)


class TestNpm(unittest.TestCase):
    def test_spec_parsing(self):
        self.assertEqual(npm_mod.parse_spec("@scope/pkg@1.2.3"), ("@scope/pkg", "1.2.3"))
        self.assertEqual(npm_mod.parse_spec("@scope/pkg"), ("@scope/pkg", None))
        self.assertEqual(npm_mod.parse_spec("left-pad@^1.3.0"), ("left-pad", "^1.3.0"))
        self.assertEqual(npm_mod.encode_name("@scope/pkg"), "@scope%2Fpkg")

    def test_integrity_hex(self):
        self.assertEqual(npm_mod.integrity_hex("sha512-" + base64.b64encode(b"\x01\x02").decode()), "0102")
        self.assertEqual(npm_mod.integrity_hex("sha1-abc"), "")
        self.assertEqual(npm_mod.integrity_hex("sha512-not*base64"), "")  # malformed: no crash

    def test_range_resolution(self):
        vs = ["1.2.0", "1.4.8", "1.4.9", "1.5.0-beta.1", "2.0.0", "3.0.0"]
        pkg = npm_mod.NpmPackage("foo", "3.0.0",
                                 {v: npm_mod.NpmVersion(v, None, "", True) for v in vs}, {"latest": "3.0.0", "next": "1.5.0-beta.1"})
        r = lambda w: npm_mod.resolve(pkg, w)[0]
        self.assertEqual(r("^1.4.0"), "1.4.9")      # not latest
        self.assertEqual(r("~1.4"), "1.4.9")
        self.assertEqual(r("1.x"), "1.4.9")
        self.assertEqual(r("1"), "1.4.9")
        self.assertEqual(r(">=2.0.0"), "3.0.0")     # latest satisfies, npm prefers it
        self.assertEqual(r("next"), "1.5.0-beta.1")  # dist-tag
        self.assertEqual(r("2.0.0"), "2.0.0")
        self.assertEqual(r(None), "3.0.0")
        self.assertIsNone(r("^9.0.0"))
        self.assertIsNone(r("1.2.0 - 1.4.0"))       # unsupported: don't guess
        self.assertEqual(npm_mod.resolve(pkg, "<2 || >2.5")[2], npm_mod.UNSUPPORTED)
        self.assertIsNone(r("1.x.3"))               # digits after a wildcard: unsupported

    def test_prerelease_rules(self):
        vs = ["1.5.0-beta.1", "1.5.0-beta.2", "1.5.0-beta.10", "1.8.0", "1.9.0-rc.1", "2.0.0"]
        pkg = npm_mod.NpmPackage("foo", "2.0.0", {v: npm_mod.NpmVersion(v, None, "", True) for v in vs},
                                 {"latest": "2.0.0"})
        r = lambda w: npm_mod.resolve(pkg, w)[0]
        self.assertEqual(r("^1.5.0-beta.1"), "1.8.0")          # other tuples' prereleases excluded
        self.assertEqual(r("~1.5.0-beta.2"), "1.5.0-beta.10")  # numeric identifiers compare as numbers
        self.assertEqual(r("1.5.0-beta.2"), "1.5.0-beta.2")
        self.assertEqual(r("^1.0.0"), "1.8.0")                 # no prereleases without asking
        self.assertFalse(npm_mod._satisfies("1.5.0-beta.1", "^1.5.0-beta.2"))

    def test_redhat_end_to_end(self):
        versions = ["3.4.2", "3.5.0", "3.5.1", "3.5.2", "3.6.0"]
        rows = [(v, f"2026-0{3 + n // 2}-1{n}T10:00:00Z", REDHAT / f"{v}.cert.b64") for n, v in enumerate(versions)]
        rows.append(("3.6.1", "2026-06-01T09:00:00Z", REDHAT / "3.6.1-malicious.cert.b64"))
        fake = FakeNpm("@redhat-cloud-services/types", rows)
        d = npm_check(fake, "@redhat-cloud-services/types", "3.6.1")
        self.assertEqual(d.verdict, FLAG)
        self.assertEqual(d.package, "npm:@redhat-cloud-services/types")
        self.assertIn("oidc-61fff775", [f for f in by_check(d, "build-identity") if f.level == FLAG][0].message)
        self.assertEqual(npm_check(fake, "@redhat-cloud-services/types", "3.6.0").verdict, ALLOW)

    def test_axios_unsigned_release_flags(self):
        rows = [("1.13.2", "2025-11-04T20:01:00Z", AXIOS / "1.13.2.cert.b64"),
                ("1.13.5", "2026-02-08T11:05:00Z", AXIOS / "1.13.5.cert.b64"),
                ("1.13.6", "2026-02-27T15:35:00Z", AXIOS / "1.13.6.cert.b64"),
                ("1.14.0", "2026-03-27T19:01:00Z", AXIOS / "1.14.0.cert.b64"),
                ("1.14.1", "2026-03-31T00:21:00Z", None)]
        fake = FakeNpm("axios", rows)
        d = npm_check(fake, "axios", "1.14.1")
        self.assertEqual(d.verdict, FLAG)
        [f] = by_check(d, "attestation-dropped")
        self.assertIn("axios/axios", f.message)
        self.assertEqual(npm_check(fake, "axios", "1.14.0").verdict, ALLOW)

    def test_axios_history_shows_real_process_change(self):
        """1.13.5 moved from pull_request on a branch to push on a tag: a real, legitimate flag."""
        rows = [("1.13.2", "2025-11-04T20:01:00Z", AXIOS / "1.13.2.cert.b64"),
                ("1.13.5", "2026-02-08T11:05:00Z", AXIOS / "1.13.5.cert.b64")]
        d = npm_check(FakeNpm("axios", rows), "axios", "1.13.5")
        fields = {f.message.split(":")[0] for f in by_check(d, "build-identity") if f.level == FLAG}
        self.assertTrue(fields)

    def test_range_checks_the_version_npm_would_install(self):
        rows = [("3.4.2", "2026-03-10T10:00:00Z", REDHAT / "3.4.2.cert.b64"),
                ("3.5.0", "2026-03-11T10:00:00Z", REDHAT / "3.5.0.cert.b64"),
                ("3.6.1", "2026-06-01T09:00:00Z", REDHAT / "3.6.1-malicious.cert.b64"),
                ("4.0.0", "2026-07-01T09:00:00Z", REDHAT / "3.5.0.cert.b64")]
        fake = FakeNpm("t", rows)
        d = npm_check(fake, "t", "^3.5.0")
        self.assertEqual(d.version, "3.6.1")
        self.assertEqual(d.verdict, FLAG)

    def test_missing_package_blocks(self):
        self.assertEqual(npm_check(FakeNpm("x", [("1.0.0", "2026-01-01T00:00:00Z", None)]), "nope", None).verdict, BLOCK)


if __name__ == "__main__":
    unittest.main()
