# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************

"""Tests for generate_crates_metadata_cache.py.

What this file tests
---------------------
parse_dash_summary()
  - Standard "crate/cratesio/-/NAME/VERSION, SPDX, STATUS, SOURCE" lines
    produce correct crate → license mappings.
  - Lines with an empty license expression are excluded.
  - Compound SPDX expressions (AND / OR / LicenseRef-*) are preserved verbatim.
  - Malformed lines (fewer than 4 comma-separated fields) are silently skipped.
  - Non-crate entries (pypi, npm) are ignored.
  - Empty file returns an empty dict.
  - Restricted crates still yield their license expression.

parse_module_bazel_lock()
  - Crate name and version are extracted from generatedRepoSpecs keys
    (format: crate_index__NAME-VERSION).
  - sha256 checksum is extracted from the attributes dict.
  - The bare "crate_index" meta-repo entry is not treated as a real crate.
  - Complex names (iceoryx2-bb-lock-free-qnx8-0.7.0) are parsed correctly.
  - Lockfiles without a crate extension return an empty dict.
  - Completely empty lockfiles return an empty dict.

generate_synthetic_cargo_lock()
  - Produces valid TOML with [[package]] entries and crates.io-index source.
  - Entries are sorted alphabetically by crate name.

TestEndToEndLicenseExtraction
  - parse_dash_summary() correctly round-trips JAR-style CSV output.
  - Full pipeline verified for a representative set of score_kyron crates.

Bazel target : //sbom/tests:test_generate_crates_metadata_cache
Run          : bazel test //sbom/tests:test_generate_crates_metadata_cache
               pytest sbom/tests/test_generate_crates_metadata_cache.py -v
"""

import json
import io
import http.client
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from scripts.generate_crates_metadata_cache import (
    _fetch_one_crate_meta,
    _cratesio_get,
    _normalize_license_expression,
    generate_cache,
    generate_synthetic_cargo_lock,
    parse_dash_summary,
    parse_module_bazel_lock,
    run_dash_license_scan,
)


class TestRunDashLicenseScan(unittest.TestCase):
    @mock.patch("scripts.generate_crates_metadata_cache.subprocess.run")
    @mock.patch("os.path.exists", return_value=True)
    def test_verbose_flag_is_not_passed_by_default(self, _mock_exists, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""

        run_dash_license_scan("Cargo.lock", "summary.txt")

        self.assertNotIn("-v", mock_run.call_args.args[0])

    @mock.patch("scripts.generate_crates_metadata_cache.subprocess.run")
    @mock.patch("os.path.exists", return_value=True)
    def test_verbose_flag_adds_v(self, _mock_exists, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""

        run_dash_license_scan("Cargo.lock", "summary.txt", verbose=True)

        self.assertIn("-v", mock_run.call_args.args[0])


class TestParseDashSummary(unittest.TestCase):
    """Tests for parse_dash_summary — the JAR summary CSV parser."""

    def _write_summary(self, content: str) -> str:
        """Helper: write content to a temp file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        self.addCleanup(os.unlink, path)
        return path

    def test_basic_parsing(self):
        """Standard summary lines produce correct crate→license mapping."""
        summary = (
            "crate/cratesio/-/serde/1.0.228, Apache-2.0 OR MIT, approved, clearlydefined\n"
            "crate/cratesio/-/tokio/1.10.0, MIT, approved, clearlydefined\n"
            "crate/cratesio/-/serde/2.0.0, Apache-2.0, approved, clearlydefined\n"
        )
        path = self._write_summary(summary)
        result = parse_dash_summary(path)

        self.assertEqual(result["serde@1.0.228"], "Apache-2.0 OR MIT")
        self.assertEqual(result["tokio@1.10.0"], "MIT")
        self.assertEqual(result["serde@2.0.0"], "Apache-2.0")

    def test_empty_license_skipped(self):
        """Entries with empty license expressions are not included."""
        summary = (
            "crate/cratesio/-/serde/1.0.228, Apache-2.0 OR MIT, approved, clearlydefined\n"
            "crate/cratesio/-/unknown-crate/0.1.0, , restricted, clearlydefined\n"
        )
        path = self._write_summary(summary)
        result = parse_dash_summary(path)

        self.assertIn("serde@1.0.228", result)
        self.assertNotIn("unknown-crate@0.1.0", result)

    def test_compound_spdx_expression(self):
        """Compound SPDX expressions (AND/OR) are preserved."""
        summary = (
            "crate/cratesio/-/ring/0.17.14, "
            "Apache-2.0 AND LicenseRef-scancode-iso-8879 AND (GPL-2.0-only AND MIT), "
            "restricted, #25641\n"
        )
        path = self._write_summary(summary)
        result = parse_dash_summary(path)

        self.assertIn("ring@0.17.14", result)
        self.assertIn("Apache-2.0", result["ring@0.17.14"])

    def test_malformed_lines_skipped(self):
        """Lines with fewer than 4 comma-separated fields are ignored."""
        summary = (
            "crate/cratesio/-/serde/1.0.228, MIT, approved, clearlydefined\n"
            "this is not a valid line\n"
            "only, two, parts\n"
            "\n"
        )
        path = self._write_summary(summary)
        result = parse_dash_summary(path)

        self.assertEqual(len(result), 1)
        self.assertEqual(result["serde@1.0.228"], "MIT")

    def test_non_crate_entries_skipped(self):
        """Non-crate entries (pypi, npm, etc.) are ignored."""
        summary = (
            "crate/cratesio/-/serde/1.0.228, MIT, approved, clearlydefined\n"
            "pypi/pypi/-/requests/2.31.0, Apache-2.0, approved, clearlydefined\n"
            "npm/npmjs/-/express/4.18.2, MIT, approved, clearlydefined\n"
        )
        path = self._write_summary(summary)
        result = parse_dash_summary(path)

        self.assertEqual(len(result), 1)
        self.assertIn("serde@1.0.228", result)

    def test_empty_file(self):
        """An empty summary file produces an empty dict."""
        path = self._write_summary("")
        result = parse_dash_summary(path)
        self.assertEqual(result, {})

    def test_restricted_crate_still_gets_license(self):
        """Restricted crates still have their license extracted."""
        summary = "crate/cratesio/-/openssl-sys/0.9.104, OpenSSL, restricted, clearlydefined\n"
        path = self._write_summary(summary)
        result = parse_dash_summary(path)

        self.assertEqual(result["openssl-sys@0.9.104"], "OpenSSL")

    def test_licenseref_expression(self):
        """LicenseRef-* expressions are preserved."""
        summary = "crate/cratesio/-/ring/0.17.14, LicenseRef-ring, restricted, clearlydefined\n"
        path = self._write_summary(summary)
        result = parse_dash_summary(path)

        self.assertEqual(result["ring@0.17.14"], "LicenseRef-ring")


class TestParseModuleBazelLock(unittest.TestCase):
    """Tests for parse_module_bazel_lock — MODULE.bazel.lock crate extraction."""

    def _write_lockfile(self, data: dict) -> str:
        """Helper: write JSON data to a temp file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        self.addCleanup(os.unlink, path)
        return path

    def test_basic_crate_extraction(self):
        """Crates are correctly extracted from generatedRepoSpecs."""
        lockfile = {
            "moduleExtensions": {
                "@@rules_rust+//crate_universe:extensions.bzl%crate": {
                    "general": {
                        "generatedRepoSpecs": {
                            "crate_index__serde-1.0.228": {
                                "attributes": {"sha256": "abc123def456"}
                            },
                            "crate_index__tokio-1.10.0": {
                                "attributes": {"sha256": "789xyz"}
                            },
                        }
                    }
                }
            }
        }
        path = self._write_lockfile(lockfile)
        result = parse_module_bazel_lock(path)

        self.assertEqual(len(result), 2)
        self.assertEqual(
            result["rules_rust++crate+crate_index__serde-1.0.228"]["version"], "1.0.228"
        )
        self.assertEqual(
            result["rules_rust++crate+crate_index__serde-1.0.228"]["checksum"],
            "abc123def456",
        )
        self.assertEqual(
            result["rules_rust++crate+crate_index__tokio-1.10.0"]["version"], "1.10.0"
        )

    def test_crate_index_meta_repo_skipped(self):
        """The crate_index meta-repo entry is not treated as a crate."""
        lockfile = {
            "moduleExtensions": {
                "crate_universe": {
                    "general": {
                        "generatedRepoSpecs": {
                            "crate_index": {"attributes": {}},
                            "crate_index__serde-1.0.228": {
                                "attributes": {"sha256": "abc"}
                            },
                        }
                    }
                }
            }
        }
        path = self._write_lockfile(lockfile)
        result = parse_module_bazel_lock(path)

        self.assertEqual(len(result), 1)
        self.assertEqual(next(iter(result.values()))["name"], "serde")

    def test_complex_crate_name(self):
        """Crate names with multiple hyphens (e.g. iceoryx2-qnx8) are parsed correctly."""
        lockfile = {
            "moduleExtensions": {
                "crate": {
                    "general": {
                        "generatedRepoSpecs": {
                            "crate_index__iceoryx2-bb-lock-free-qnx8-0.7.0": {
                                "attributes": {"sha256": "xyz"}
                            },
                        }
                    }
                }
            }
        }
        path = self._write_lockfile(lockfile)
        result = parse_module_bazel_lock(path)

        self.assertEqual(len(result), 1)
        entry = next(iter(result.values()))
        self.assertEqual(entry["name"], "iceoryx2-bb-lock-free-qnx8")
        self.assertEqual(entry["version"], "0.7.0")

    def test_no_crate_extension(self):
        """Lockfile without crate extension returns empty dict."""
        lockfile = {"moduleExtensions": {"some_other_extension": {"general": {}}}}
        path = self._write_lockfile(lockfile)
        result = parse_module_bazel_lock(path)

        self.assertEqual(result, {})

    def test_empty_lockfile(self):
        """Lockfile with no moduleExtensions returns empty dict."""
        path = self._write_lockfile({})
        result = parse_module_bazel_lock(path)
        self.assertEqual(result, {})


class TestGenerateSyntheticCargoLock(unittest.TestCase):
    """Tests for generate_synthetic_cargo_lock."""

    def test_generates_valid_toml(self):
        """Generated Cargo.lock has correct TOML structure."""
        crates = {
            "serde": {"name": "serde", "version": "1.0.228", "checksum": "abc"},
            "tokio": {"name": "tokio", "version": "1.10.0", "checksum": "def"},
        }
        fd, path = tempfile.mkstemp(suffix=".lock")
        os.close(fd)
        self.addCleanup(os.unlink, path)

        generate_synthetic_cargo_lock(crates, path)

        with open(path) as f:
            content = f.read()

        self.assertIn("version = 4", content)
        self.assertIn('name = "serde"', content)
        self.assertIn('version = "1.0.228"', content)
        self.assertIn('name = "tokio"', content)
        self.assertIn("[[package]]", content)
        self.assertIn("crates.io-index", content)

    def test_entries_are_sorted(self):
        """Cargo.lock entries are sorted by crate name."""
        crates = {
            "z-crate": {"name": "z-crate", "version": "1.0.0", "checksum": ""},
            "a-crate": {"name": "a-crate", "version": "2.0.0", "checksum": ""},
        }
        fd, path = tempfile.mkstemp(suffix=".lock")
        os.close(fd)
        self.addCleanup(os.unlink, path)

        generate_synthetic_cargo_lock(crates, path)

        with open(path) as f:
            content = f.read()

        a_pos = content.index('name = "a-crate"')
        z_pos = content.index('name = "z-crate"')
        self.assertLess(a_pos, z_pos)


class TestCratesIoLicenseFallback(unittest.TestCase):
    """Tests for crates.io-first metadata behavior in generate_cache()."""

    def _write_module_lock(self, crates: list[tuple[str, str, str]]) -> str:
        """Create a minimal MODULE.bazel.lock with crate_universe specs.

        Args:
            crates: List of (name, version, sha256)
        """
        specs = {}
        for name, version, sha256 in crates:
            specs[f"crate_index__{name}-{version}"] = {
                "attributes": {
                    "sha256": sha256,
                    "urls": [
                        f"https://static.crates.io/crates/{name}/{version}/download"
                    ],
                }
            }

        lockfile = {
            "moduleExtensions": {
                "@@rules_rust+//crate_universe:extensions.bzl%crate": {
                    "general": {"generatedRepoSpecs": specs}
                }
            }
        }

        fd, path = tempfile.mkstemp(suffix=".lock")
        with os.fdopen(fd, "w") as f:
            json.dump(lockfile, f)
        self.addCleanup(os.unlink, path)
        return path

    @mock.patch("scripts.generate_crates_metadata_cache._cratesio_get")
    def test_cache_keeps_versions_from_each_lockfile(self, mock_get):
        versions = {"1.3.0": ("a" * 64, "MIT"), "2.0.1": ("b" * 64, "Apache-2.0")}
        mock_get.side_effect = lambda url: {
            "version": {"license": versions.get(url.rsplit("/", 1)[-1], ("", ""))[1]}
        }
        module_lock = self._write_module_lock(
            [
                ("shlex", version, checksum)
                for version, (checksum, _) in versions.items()
            ]
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            cargo_lock = os.path.join(tmpdir, "Cargo.lock")
            with open(cargo_lock, "w") as f:
                for version, (checksum, _) in versions.items():
                    f.write(
                        f'[[package]]\nname = "shlex"\nversion = "{version}"\n'
                        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                        f'checksum = "{checksum}"\n'
                    )
            for inputs in (
                {"cargo_lock_path": cargo_lock},
                {"module_lock_paths": [module_lock]},
                {
                    "cargo_lock_path": cargo_lock,
                    "module_lock_paths": [module_lock, module_lock],
                },
            ):
                with self.subTest(inputs=inputs):
                    cache = generate_cache(**inputs)
                    self.assertEqual(set(cache), {f"shlex@{v}" for v in versions})
                    for version, (checksum, license_expr) in versions.items():
                        entry = cache[f"shlex@{version}"]
                        self.assertEqual(entry["checksum"], checksum)
                        self.assertEqual(entry["license"], license_expr)
                        self.assertEqual(entry["purl"], f"pkg:cargo/shlex@{version}")

    def test_normalize_license_expression_slash_to_or(self):
        """crates.io slash separator must be normalized to SPDX OR."""
        self.assertEqual(
            _normalize_license_expression("MIT/Apache-2.0"),
            "MIT OR Apache-2.0",
        )

    @mock.patch(
        "scripts.generate_crates_metadata_cache.fetch_crate_metadata_from_cratesio"
    )
    def test_generate_cache_uses_cratesio_license_when_dash_disabled(self, mock_fetch):
        """Without dash-license-scan, crates.io license is used as fallback source."""
        mock_fetch.return_value = {
            "serde@1.0.228": {
                "license": "MIT OR Apache-2.0",
                "description": "Serde framework",
                "supplier": "serde-rs",
            }
        }
        module_lock = self._write_module_lock([("serde", "1.0.228", "abc123")])

        cache = generate_cache(
            module_lock_paths=[module_lock], use_dash_license_scan=False
        )

        self.assertEqual(cache["serde@1.0.228"]["license"], "MIT OR Apache-2.0")
        self.assertEqual(cache["serde@1.0.228"]["description"], "Serde framework")
        self.assertEqual(cache["serde@1.0.228"]["supplier"], "serde-rs")

    @mock.patch("scripts.generate_crates_metadata_cache.parse_dash_summary")
    @mock.patch("scripts.generate_crates_metadata_cache.run_dash_license_scan")
    @mock.patch(
        "scripts.generate_crates_metadata_cache.fetch_crate_metadata_from_cratesio"
    )
    def test_dash_license_takes_precedence_over_cratesio(
        self,
        mock_fetch,
        _mock_run_dash,
        mock_parse_dash,
    ):
        """When enabled, dash-license-scan license must override crates.io license."""
        mock_fetch.return_value = {
            "serde@1.0.228": {
                "license": "MIT OR Apache-2.0",
                "description": "Serde framework",
                "supplier": "serde-rs",
            }
        }
        mock_parse_dash.return_value = {"serde@1.0.228": "Apache-2.0"}
        module_lock = self._write_module_lock([("serde", "1.0.228", "abc123")])

        cache = generate_cache(
            module_lock_paths=[module_lock], use_dash_license_scan=True
        )

        self.assertEqual(cache["serde@1.0.228"]["license"], "Apache-2.0")

    @mock.patch("scripts.generate_crates_metadata_cache._cratesio_get")
    def test_fetch_one_crate_meta_uses_locked_version_for_license(self, mock_get):
        """License must come from the locked version, not the crate's latest release.

        The crates.io crate-level endpoint has no license field at all (it only
        exists on the per-version endpoint), so a crate that changed its license
        between the locked version and the latest release must still report the
        locked version's license, not the latest one's.
        """

        def fake_get(url):
            if url == "https://crates.io/api/v1/crates/relicensed":
                return {
                    "crate": {"description": "A crate", "repository": ""},
                }
            if url == "https://crates.io/api/v1/crates/relicensed/1.0.0":
                return {"version": {"license": "MIT"}}
            if url == "https://crates.io/api/v1/crates/relicensed/2.0.0":
                return {"version": {"license": "Apache-2.0"}}
            raise AssertionError(f"unexpected URL: {url}")

        mock_get.side_effect = fake_get

        name, meta = _fetch_one_crate_meta("relicensed", "1.0.0")
        self.assertEqual(meta["license"], "MIT")


class TestManifestLicenses(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        patcher = mock.patch("scripts.generate_crates_metadata_cache._cratesio_get")
        self.get = patcher.start()
        self.addCleanup(patcher.stop)
        self.get.side_effect = lambda url: (
            {"version": {"license": "BSD-3-Clause"}}
            if url.endswith(("/1.3.0", "/2.0.1"))
            else {"crate": {"description": "A crate"}}
        )

    def collect(self, manifests, registry=True, hub="crate_index", edge_only=False):
        specs, repos, files = {}, [], {}
        for (name, version), content in manifests.items():
            repo_suffix = f"{hub}__{name}-{version}".replace("+", "-")
            repo = f"rules_rust++crate+{repo_suffix}"
            repos.append(repo)
            attrs = {"sha256": "a" * 64}
            attrs.update(
                {
                    "urls": [
                        f"https://static.crates.io/crates/{name}/{version}/download"
                    ],
                    "strip_prefix": f"{name}-{version}",
                }
                if registry
                else {"remote": "https://example.org/fork.git"}
            )
            specs[repo_suffix] = {"attributes": attrs}
            if content is not None:
                path = self.root / f"{name}-{version}.toml"
                path.write_text(content)
                files[repo] = str(path)
        lock = self.root / "MODULE.bazel.lock"
        lock.write_text(
            json.dumps(
                {
                    "moduleExtensions": {
                        "@@rules_rust+//crate_universe:extensions.bzl%crate": {
                            "general": {"generatedRepoSpecs": specs}
                        }
                    }
                }
            )
        )
        deps = self.root / "deps.json"
        deps.write_text(
            json.dumps(
                {
                    "external_repos": [] if edge_only else repos,
                    "crate_manifests": files,
                    "external_dep_edges": [f"app+::{repo}+" for repo in repos]
                    + ["invalid", "app+::"]
                    if edge_only
                    else [],
                }
            )
        )
        return generate_cache(module_lock_paths=[str(lock)], deps_path=str(deps))

    def test_edge_destinations_collect_and_validate_crate_metadata(self):
        manifest = '[package]\nname="shlex"\nversion="1.3.0"\nlicense="MIT"'
        for content in (manifest, None):
            with self.subTest(content=content):
                cache = self.collect({("shlex", "1.3.0"): content}, edge_only=True)
                repo = "rules_rust++crate+crate_index__shlex-1.3.0"
                self.assertEqual(set(cache), {"repo:" + repo})
                entry = cache["repo:" + repo]
                self.assertEqual(entry["checksum"], "a" * 64)
                self.assertEqual(entry["license"], "MIT" if content else "BSD-3-Clause")
        self.get.reset_mock()
        with self.assertRaisesRegex(ValueError, "Manifest identity mismatch"):
            self.collect(
                {("shlex", "1.3.0"): manifest.replace("1.3.0", "2.0.1")}, edge_only=True
            )
        self.get.assert_not_called()

    def test_named_hubs_preserve_package_identity_and_source(self):
        manifest = '[package]\nname="anstream"\nversion="1.0.0"\nlicense="MIT"'
        self.get.side_effect = lambda url: {"version": {"license": "Apache-2.0"}}
        for hub in ("crates", "score_crates", "custom_hub"):
            for content in (manifest, None):
                with self.subTest(hub=hub, content=content):
                    self.get.reset_mock()
                    cache = self.collect({("anstream", "1.0.0"): content}, hub=hub)
                    entry = cache[f"repo:rules_rust++crate+{hub}__anstream-1.0.0"]
                    self.assertEqual(entry["name"], "anstream")
                    self.assertEqual(entry["version"], "1.0.0")
                    self.assertEqual(entry["checksum"], "a" * 64)
                    self.assertEqual(
                        entry["license"], "MIT" if content else "Apache-2.0"
                    )
                    if not content:
                        self.get.assert_any_call(
                            "https://crates.io/api/v1/crates/anstream/1.0.0"
                        )

    def test_same_package_in_two_hubs_keeps_each_source(self):
        self.collect({("shlex", "1.3.0"): None})
        lock = self.root / "MODULE.bazel.lock"
        data = json.loads(lock.read_text())
        extension = next(iter(data["moduleExtensions"].values()))["general"]
        specs = extension["generatedRepoSpecs"]
        specs["custom_hub__shlex-1.3.0"] = {
            "attributes": {
                "sha256": "b" * 64,
                "urls": ["https://example.org/fork.tar.gz"],
            }
        }
        first = "rules_rust++crate+crate_index__shlex-1.3.0"
        second = "rules_rust++crate+custom_hub__shlex-1.3.0"
        deps = self.root / "deps.json"
        deps.write_text(json.dumps({"external_repos": [first, second]}))
        for entries in (list(specs.items()), list(reversed(specs.items()))):
            with self.subTest(order=[key for key, _ in entries]):
                extension["generatedRepoSpecs"] = dict(entries)
                lock.write_text(json.dumps(data))
                self.get.reset_mock()
                cache = generate_cache(
                    module_lock_paths=[str(lock)], deps_path=str(deps)
                )
                self.assertEqual(cache["repo:" + first]["checksum"], "a" * 64)
                self.assertEqual(cache["repo:" + first]["license"], "BSD-3-Clause")
                self.assertEqual(cache["repo:" + second]["checksum"], "b" * 64)
                self.assertEqual(cache["repo:" + second]["license"], "")
                self.assertIn(
                    "confirmed crates.io source",
                    cache["repo:" + second]["license_error"],
                )
                self.get.assert_any_call("https://crates.io/api/v1/crates/shlex/1.3.0")

    def test_local_versions_take_precedence_without_license_requests(self):
        licenses = {"1.3.0": "MIT", "2.0.1": "Apache-2.0"}
        cache = self.collect(
            {
                (
                    "shlex",
                    version,
                ): f'[package]\nname="shlex"\nversion="{version}"\nlicense="{license}"'
                for version, license in licenses.items()
            }
        )
        for version, license in licenses.items():
            entry = cache[f"repo:rules_rust++crate+crate_index__shlex-{version}"]
            self.assertEqual(entry["license"], license)
            self.assertTrue(entry["license_source"].endswith(f"shlex-{version}.toml"))
        self.assertEqual(
            self.get.call_args_list,
            [mock.call("https://crates.io/api/v1/crates/shlex")] * 2,
        )

    def test_normalized_version_uses_exact_manifest_and_api_identity(self):
        version = "0.11.1+wasi-snapshot-preview1"
        manifest = f'[package]\nname="wasi"\nversion="{version}"\nlicense="MIT"'
        self.get.side_effect = lambda url: {"version": {"license": "Apache-2.0"}}
        for registry, content in ((True, manifest), (True, None), (False, manifest)):
            with self.subTest(registry=registry, content=content):
                self.get.reset_mock()
                entry = next(
                    iter(self.collect({("wasi", version): content}, registry).values())
                )
                self.assertEqual(entry["version"], version)
                self.assertEqual(entry["purl"], f"pkg:cargo/wasi@{version}")
                self.assertEqual(entry["license"], "MIT" if content else "Apache-2.0")
                calls = [c.args[0] for c in self.get.call_args_list]
                self.assertEqual(
                    f"https://crates.io/api/v1/crates/wasi/{version}" in calls,
                    content is None,
                )

    def test_exact_archive_version_does_not_accept_a_different_prerelease(self):
        with self.assertRaisesRegex(ValueError, "Manifest identity mismatch"):
            self.collect(
                {
                    (
                        "wasi",
                        "0.11.1+wasi-snapshot-preview1",
                    ): '[package]\nname="wasi"\nversion="0.11.1-wasi-snapshot-preview1"\nlicense="MIT"'
                }
            )
        self.get.assert_not_called()

    def test_cargo_lock_only_preserves_selected_legacy_and_modern_crates(self):
        cargo = self.root / "Cargo.lock"
        cargo.write_text("""[[package]]
name = "shlex"
version = "1.3.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "archive-hash"
[[package]]
name = "shlex"
version = "2.0.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "other-hash"
""")
        for prefix in (
            "rules_rust++crate+crate_index__",
            "crates_io__",
            "score_crates__",
        ):
            with self.subTest(prefix=prefix):
                repo = prefix + "shlex-1.3.0"
                deps = self.root / "deps.json"
                deps.write_text(json.dumps({"external_repos": [repo]}))
                cache = generate_cache(cargo_lock_path=str(cargo), deps_path=str(deps))
                self.assertEqual(set(cache), {"repo:" + repo})
                self.assertEqual(cache["repo:" + repo]["checksum"], "archive-hash")
                self.assertEqual(cache["repo:" + repo]["license"], "BSD-3-Clause")

        # A second source for the same name/version is not a unique association.
        cargo.write_text(
            cargo.read_text()
            + """[[package]]
name = "shlex"
version = "1.3.0"
source = "git+https://example.org/fork.git#abc"
"""
        )
        self.get.reset_mock()
        entry = next(
            iter(
                generate_cache(cargo_lock_path=str(cargo), deps_path=str(deps)).values()
            )
        )
        self.assertEqual(entry["checksum"], "")
        self.assertEqual(entry["license"], "")
        self.assertNotIn(
            mock.call("https://crates.io/api/v1/crates/shlex/1.3.0"),
            self.get.call_args_list,
        )

    def test_module_git_source_is_not_replaced_by_cargo_registry_entry(self):
        self.collect({("shlex", "1.3.0"): None}, registry=False)
        cargo = self.root / "Cargo.lock"
        cargo.write_text("""[[package]]
name = "shlex"
version = "1.3.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "registry-hash"
""")
        self.get.reset_mock()
        cache = generate_cache(
            cargo_lock_path=str(cargo),
            module_lock_paths=[str(self.root / "MODULE.bazel.lock")],
            deps_path=str(self.root / "deps.json"),
        )
        entry = next(iter(cache.values()))
        self.assertEqual(entry["license"], "")
        self.assertNotEqual(entry["checksum"], "registry-hash")
        self.assertNotIn(
            mock.call("https://crates.io/api/v1/crates/shlex/1.3.0"),
            self.get.call_args_list,
        )

    def test_missing_and_unsupported_declarations_fall_back(self):
        manifest = '[package]\nname="shlex"\nversion="1.3.0"\n'
        for content in (
            None,
            manifest,
            manifest + "license.workspace=true",
            manifest + 'license-file="LICENSE"',
        ):
            with self.subTest(content=content):
                self.get.reset_mock()
                entry = next(iter(self.collect({("shlex", "1.3.0"): content}).values()))
                self.assertEqual(entry["license"], "BSD-3-Clause")
                self.assertEqual(
                    entry["license_source"],
                    "https://crates.io/api/v1/crates/shlex/1.3.0",
                )
                self.get.assert_any_call(entry["license_source"])

    def test_api_failure_and_empty_response_have_distinct_reasons(self):
        manifest = '[package]\nname="shlex"\nversion="1.3.0"\nlicense.workspace=true'
        for response, failure, reason in (
            ({"version": {"license": None}}, None, "API response has no license"),
            (None, urllib.error.URLError("offline"), "API request failed"),
        ):
            with self.subTest(reason=reason):
                self.get.side_effect = failure
                self.get.return_value = response
                with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                    entry = next(
                        iter(self.collect({("shlex", "1.3.0"): manifest}).values())
                    )
                self.assertEqual(entry["license"], "")
                self.assertIn("Workspace license inheritance", entry["license_error"])
                self.assertIn(reason, entry["license_error"])
                self.assertIn(reason, stderr.getvalue())

    def test_fork_never_receives_registry_license(self):
        for name in ("shlex", "shlex-qnx8"):
            with self.subTest(name=name):
                self.get.reset_mock()
                entry = next(
                    iter(self.collect({(name, "1.3.0"): None}, registry=False).values())
                )
                self.assertEqual(entry["license"], "")
                self.assertIn("confirmed crates.io source", entry["license_error"])
                self.assertFalse(
                    any(c.args[0].endswith("/1.3.0") for c in self.get.call_args_list)
                )

    def test_identity_mismatch_fails_before_api_lookup(self):
        for name, version in (("another-crate", "1.3.0"), ("shlex", "2.0.1")):
            with self.subTest(name=name, version=version):
                content = (
                    f'[package]\nname="{name}"\nversion="{version}"\nlicense="MIT"'
                )
                with self.assertRaisesRegex(ValueError, "Manifest identity mismatch"):
                    self.collect({("shlex", "1.3.0"): content})
        self.get.assert_not_called()

    def test_other_metadata_failure_preserves_local_license(self):
        self.get.side_effect = urllib.error.URLError("offline")
        entry = next(
            iter(
                self.collect(
                    {
                        (
                            "shlex",
                            "1.3.0",
                        ): '[package]\nname="shlex"\nversion="1.3.0"\nlicense="MIT"'
                    }
                ).values()
            )
        )
        self.assertEqual(entry["license"], "MIT")
        self.assertNotIn("license_error", entry)

    @mock.patch("scripts.generate_crates_metadata_cache.time.sleep")
    @mock.patch("scripts.generate_crates_metadata_cache.urllib.request.urlopen")
    def test_response_read_failure_does_not_discard_local_licenses(
        self, urlopen, _sleep
    ):
        self.get.side_effect = _cratesio_get
        response = urlopen.return_value.__enter__.return_value
        for error in (
            http.client.IncompleteRead(b"partial", 10),
            ConnectionResetError("reset"),
        ):
            response.read.side_effect = error
            for content in (
                '[package]\nname="shlex"\nversion="1.3.0"\nlicense="MIT"',
                None,
            ):
                with self.subTest(error=error, content=content):
                    urlopen.reset_mock()
                    entry = next(
                        iter(self.collect({("shlex", "1.3.0"): content}).values())
                    )
                    self.assertEqual(urlopen.call_count, 3 if content else 6)
                    self.assertEqual(entry["license"], "MIT" if content else "")
                    if not content:
                        self.assertIn(str(error), entry["license_error"])


class TestCratesIoRequests(unittest.TestCase):
    @mock.patch("scripts.generate_crates_metadata_cache.time.sleep")
    @mock.patch("scripts.generate_crates_metadata_cache.urllib.request.urlopen")
    def test_response_read_failure_is_retried(self, urlopen, _sleep):
        response = urlopen.return_value.__enter__.return_value
        for error in (
            http.client.IncompleteRead(b"partial", 10),
            ConnectionResetError("reset"),
        ):
            with self.subTest(error=error):
                urlopen.reset_mock()
                response.read.side_effect = [error, b"{}"]
                self.assertEqual(
                    _cratesio_get("https://crates.io/api/v1/crates/shlex"), {}
                )
                self.assertEqual(urlopen.call_count, 2)

    @mock.patch("scripts.generate_crates_metadata_cache.time.sleep")
    @mock.patch(
        "scripts.generate_crates_metadata_cache.time.monotonic", return_value=100.0
    )
    @mock.patch("scripts.generate_crates_metadata_cache.urllib.request.urlopen")
    def test_rate_limit_and_bounded_retries(self, urlopen, _clock, sleep):
        module = "scripts.generate_crates_metadata_cache"
        with mock.patch(module + "._last_request", 100.0):
            urlopen.side_effect = [urllib.error.URLError("offline"), io.BytesIO(b"{}")]
            self.assertEqual(_cratesio_get("https://crates.io/api/v1/crates/shlex"), {})
            self.assertEqual(urlopen.call_count, 2)
            self.assertIn(mock.call(1.0), sleep.call_args_list)
            for status, attempts in ((404, 1), (429, 3), (503, 3)):
                with self.subTest(status=status):
                    urlopen.reset_mock()
                    urlopen.side_effect = urllib.error.HTTPError(
                        "url", status, "error", {}, None
                    )
                    with self.assertRaises(urllib.error.HTTPError):
                        _cratesio_get("https://crates.io/api/v1/crates/shlex")
                    self.assertEqual(urlopen.call_count, attempts)


class TestEndToEndLicenseExtraction(unittest.TestCase):
    """Integration tests verifying the full license extraction pipeline.

    These tests verify that the parse_dash_summary function correctly
    handles the output format of the Eclipse dash-licenses JAR.
    """

    def _write_summary(self, content: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        self.addCleanup(os.unlink, path)
        return path

    def test_summary_format_round_trip(self):
        """parse_dash_summary correctly maps crate names from JAR-style CSV output."""
        summary = (
            "crate/cratesio/-/serde/1.0.228, Apache-2.0 OR MIT, approved, clearlydefined\n"
            "crate/cratesio/-/tokio/1.10.0, MIT, approved, clearlydefined\n"
        )
        path = self._write_summary(summary)
        license_map = parse_dash_summary(path)

        self.assertEqual(license_map["serde@1.0.228"], "Apache-2.0 OR MIT")
        self.assertEqual(license_map["tokio@1.10.0"], "MIT")

    def test_kyron_style_crates(self):
        """Verify license extraction works for crates typical in the score_kyron module."""
        crate_names = [
            "proc-macro2@1.0.92",
            "quote@1.0.37",
            "syn@2.0.96",
            "iceoryx2@0.7.0",
        ]

        summary = (
            "crate/cratesio/-/proc-macro2/1.0.92, Apache-2.0 OR MIT, approved, clearlydefined\n"
            "crate/cratesio/-/quote/1.0.37, Apache-2.0 OR MIT, approved, clearlydefined\n"
            "crate/cratesio/-/syn/2.0.96, Apache-2.0 OR MIT, approved, clearlydefined\n"
            "crate/cratesio/-/iceoryx2/0.7.0, Apache-2.0 OR MIT, approved, clearlydefined\n"
        )
        path = self._write_summary(summary)
        license_map = parse_dash_summary(path)

        for name in crate_names:
            self.assertIn(name, license_map, f"Missing license for {name}")
            self.assertTrue(license_map[name], f"Empty license for {name}")
