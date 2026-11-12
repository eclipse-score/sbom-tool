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
"""Tests for declared and concluded licenses.

What this file tests
---------------------
Concluded license priority
  - sbom_ext metadata > dash-license-scan > declared license > defaults,
    whatever order the collectors run in.
  - A declared license is kept even when a higher-priority conclusion wins.

Output
  - SPDX licenseDeclared and licenseConcluded are filled separately, and
    licenseComments explains the source and any difference.
  - CycloneDX acknowledges the concluded license and keeps the declared one
    and the explanation as properties.

Collectors
  - Crate cache entries: manifest, registry, dash result and older caches.
  - cdxgen licenses replace BCR defaults but not sbom_ext metadata.
  - Duplicates keep the highest-priority license.
  - The generator writes both licenses from a crate cache to both reports.

Bazel target : //tests:test_licenses
Run          : bazel test //tests:test_licenses
"""

import itertools
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from internal.generator.cyclonedx_formatter import generate_cyclonedx
from internal.generator.licenses import (
    BCR_TABLE,
    CARGO_MANIFEST,
    CDXGEN,
    CRATE_CACHE,
    CRATES_IO,
    DASH,
    USER,
    apply_crate_license,
    compare_licenses,
    set_declared_license,
    set_license,
    spdx_license_fields,
)
from internal.generator.sbom_generator import (
    apply_known_licenses,
    deduplicate_components,
    enrich_components_from_cpp_cache,
    main,
    resolve_component,
)
from internal.generator.spdx_formatter import generate_spdx


def _declared(expression, source=CARGO_MANIFEST, **fields):
    component = dict(fields)
    set_declared_license(component, expression, source)
    return component


class TestConcludedPriority(unittest.TestCase):
    def test_priority_does_not_depend_on_collection_order(self):
        candidates = [("MIT", USER), ("Apache-2.0", DASH), ("BSD-3-Clause", CDXGEN)]
        candidates.append(("Zlib", BCR_TABLE))
        for count in range(1, len(candidates) + 1):
            for chosen in itertools.permutations(candidates, count):
                with self.subTest(order=[source for _, source in chosen]):
                    component = {}
                    for expression, source in chosen:
                        if source == CDXGEN:
                            set_declared_license(component, expression, source)
                        else:
                            set_license(component, expression, source)
                    winner = min(chosen, key=candidates.index)
                    self.assertEqual(component["license"], winner[0])
                    self.assertEqual(component["license_source"], winner[1])
                    self.assertEqual(
                        component.get("license_declared"),
                        "BSD-3-Clause" if ("BSD-3-Clause", CDXGEN) in chosen else None,
                    )

    def test_empty_values_are_not_candidates(self):
        component = {}
        for value in ("", "  ", "NOASSERTION", None):
            set_license(component, value, USER)
            set_declared_license(component, value, CDXGEN)
        self.assertEqual(component, {})


class TestLicenseFields(unittest.TestCase):
    def test_spdx_fields_and_comments(self):
        dash = {"license": "Apache-2.0", "license_source": DASH}
        error = {"license_error": "Cargo.toml unavailable"}
        cases = [
            (
                _declared("MIT"),
                "MIT",
                "MIT",
                "Concluded license adopts the license declared in Cargo.toml.",
            ),
            (
                _declared("MIT OR Apache-2.0", **dash),
                "MIT OR Apache-2.0",
                "Apache-2.0",
                "Concluded from dash-license-scan, which selects from the "
                "alternatives of the license declared in Cargo.toml "
                "(MIT OR Apache-2.0).",
            ),
            (
                _declared("MIT", **dash),
                "MIT",
                "Apache-2.0",
                "Concluded from dash-license-scan. This differs from the license "
                "declared in Cargo.toml (MIT).",
            ),
            (
                _declared(
                    "MIT OR Apache-2.0", **{**dash, "license": "Apache-2.0 or MIT"}
                ),
                "MIT OR Apache-2.0",
                "Apache-2.0 OR MIT",
                "Concluded from dash-license-scan; matches the license declared "
                "in Cargo.toml.",
            ),
            (
                {**dash, **error},
                "NOASSERTION",
                "Apache-2.0",
                "Concluded from dash-license-scan; no declared license was found: "
                "Cargo.toml unavailable.",
            ),
            (
                {"license": "BSL-1.0", "license_source": BCR_TABLE},
                "NOASSERTION",
                "BSL-1.0",
                "Concluded from the BCR known-license table; no declared license "
                "was found.",
            ),
            (
                {"name": "score_baselibs"},
                "NOASSERTION",
                "Apache-2.0",
                "Concluded from the Eclipse S-CORE project default; no declared "
                "license was found.",
            ),
            (
                error,
                "NOASSERTION",
                "NOASSERTION",
                "No license was found: Cargo.toml unavailable.",
            ),
            # A license of unknown origin keeps the earlier output.
            ({"license": "MIT"}, "MIT", "MIT", None),
            (
                {"license": "NOASSERTION", "license_source": DASH},
                "NOASSERTION",
                "NOASSERTION",
                None,
            ),
        ]
        for component, declared, concluded, comment in cases:
            with self.subTest(component=component):
                fields = spdx_license_fields(component)
                self.assertEqual(fields["licenseDeclared"], declared)
                self.assertEqual(fields["licenseConcluded"], concluded)
                self.assertEqual(fields.get("licenseComments"), comment)

    def test_compare_licenses(self):
        for declared, concluded, expected in (
            ("MIT AND Zlib", "Zlib and MIT", "matches"),
            ("MIT OR Zlib OR BSL-1.0", "Zlib OR MIT", "selects"),
            ("MIT OR Zlib", "MIT AND Zlib", "differs"),
            ("MIT AND Zlib", "MIT", "differs"),
            ("MIT OR (A AND B)", "(A AND B) OR MIT", "differs"),
            ("MIT", "Apache-2.0", "differs"),
        ):
            with self.subTest(declared=declared, concluded=concluded):
                self.assertEqual(compare_licenses(declared, concluded), expected)

    def test_root_package_declares_component_license(self):
        config = {"component_name": "app", "component_license": "MIT"}
        root = generate_spdx([], config, "2026-01-01T00:00:00Z")["packages"][0]
        self.assertEqual(root["licenseDeclared"], "MIT")
        self.assertEqual(root["licenseConcluded"], "MIT")
        self.assertIn("sbom() component_license attribute", root["licenseComments"])

    def test_cyclonedx_root_reports_the_spdx_root_licenses(self):
        for config, concluded, declared in (
            ({"component_name": "app", "component_license": "MIT"}, "MIT", "MIT"),
            ({"component_name": "score_app"}, "Apache-2.0", None),
            ({"component_name": "app"}, None, None),
        ):
            with self.subTest(config=config):
                timestamp = "2026-01-01T00:00:00Z"
                spdx = generate_spdx([], config, timestamp)["packages"][0]
                cdx = generate_cyclonedx([], config, timestamp)
                root = cdx["metadata"]["component"]
                license_entry = {"id": concluded, "acknowledgement": "concluded"}
                self.assertEqual(
                    root.get("licenses"),
                    [{"license": license_entry}] if concluded else None,
                )
                properties = {p["name"]: p["value"] for p in root.get("properties", [])}
                self.assertEqual(properties.get("score:license:declared"), declared)
                self.assertEqual(
                    properties.get("score:license:comments"),
                    spdx.get("licenseComments"),
                )

    def test_cyclonedx_acknowledges_the_concluded_license(self):
        component = _declared(
            "MIT",
            name="serde",
            version="1.0",
            license="Apache-2.0",
            license_source=DASH,
        )
        cdx = generate_cyclonedx([component], {}, "2026-01-01T00:00:00Z")
        serde = cdx["components"][0]
        self.assertEqual(
            serde["licenses"],
            [{"license": {"id": "Apache-2.0", "acknowledgement": "concluded"}}],
        )
        properties = {p["name"]: p["value"] for p in serde["properties"]}
        self.assertEqual(properties["score:license:declared"], "MIT")
        self.assertIn("differs", properties["score:license:comments"])


class TestCollectors(unittest.TestCase):
    def test_crate_cache_entries(self):
        url = "https://crates.io/api/v1/crates/serde/1.0.0"
        manifest = {"license": "MIT", "license_source": "x/Cargo.toml"}
        cases = [
            (manifest, "MIT", CARGO_MANIFEST, CARGO_MANIFEST),
            ({"license": "MIT", "license_source": url}, "MIT", CRATES_IO, CRATES_IO),
            ({"license": "MIT"}, "MIT", CRATE_CACHE, CRATE_CACHE),
            (
                {**manifest, "license_concluded": "Apache-2.0"},
                "MIT",
                CARGO_MANIFEST,
                DASH,
            ),
            ({"license": "MIT", "license_source": DASH}, None, None, DASH),
            ({"license": "MIT", "purl_explicit": False}, None, None, USER),
        ]
        for entry, declared, declared_source, source in cases:
            with self.subTest(entry=entry):
                component = {}
                apply_crate_license(component, entry)
                self.assertEqual(component.get("license_declared"), declared)
                self.assertEqual(
                    component.get("license_declared_source"), declared_source
                )
                self.assertEqual(component["license_source"], source)

    def test_cdxgen_replaces_defaults_but_not_user_metadata(self):
        cdxgen = [{"name": "boost", "license": "BSL-1.0 OR MIT"}]
        for user_license, expected, source in (
            (None, "BSL-1.0 OR MIT", CDXGEN),
            ("BSL-1.0", "BSL-1.0", USER),
        ):
            with self.subTest(user_license=user_license):
                metadata = {"modules": {"boost": {"version": "1.87.0"}}}
                if user_license:
                    metadata["licenses"] = {"boost": {"license": user_license}}
                apply_known_licenses(metadata)
                component = resolve_component("boost+", metadata)
                self.assertEqual(
                    component["license_source"], USER if user_license else BCR_TABLE
                )
                enrich_components_from_cpp_cache([component], cdxgen, metadata)
                self.assertEqual(component["license"], expected)
                self.assertEqual(component["license_source"], source)
                self.assertEqual(component["license_declared"], "BSL-1.0 OR MIT")

    def test_cdxgen_of_another_release_is_ignored(self):
        for selected, scanned, expected in (
            ("1.87.0", "1.70.0", None),
            ("1.87.0.bcr.1", "1.87.0", "MIT"),
            ("1.87.0", "v1.87.0", "MIT"),
        ):
            with self.subTest(selected=selected, scanned=scanned):
                metadata = {"modules": {"boost": {"version": selected}}}
                apply_known_licenses(metadata)
                component = resolve_component("boost+", metadata)
                cdxgen = [
                    {"name": "boost", "version": scanned, "license": "MIT"},
                ]
                enrich_components_from_cpp_cache([component], cdxgen, metadata)
                self.assertEqual(component.get("license_declared"), expected)
                self.assertEqual(component["license"], expected or "BSL-1.0")

    def test_cdxgen_uses_the_selected_release_in_any_scan_order(self):
        selected = {"name": "boost", "version": "1.87.0", "license": "MIT"}
        other = {"name": "boost", "version": "1.70.0", "license": "Zlib"}
        for cdxgen in ([selected, other], [other, selected]):
            with self.subTest(order=[entry["version"] for entry in cdxgen]):
                metadata = {"modules": {"boost": {"version": "1.87.0"}}}
                component = resolve_component("boost+", metadata)
                enrich_components_from_cpp_cache([component], cdxgen, metadata)
                self.assertEqual(component["license_declared"], "MIT")

    def test_duplicates_keep_highest_priority_license(self):
        identity = {"name": "lib", "version": "1.0", "purl": "pkg:generic/lib@1.0"}
        declared = _declared("MIT", CDXGEN, **identity)
        default = {**identity, "license": "Zlib", "license_source": BCR_TABLE}
        for order in ((default, declared), (declared, default)):
            with self.subTest(first=order[0]["license"]):
                merged = deduplicate_components([dict(c) for c in order])
                self.assertEqual(len(merged), 1)
                self.assertEqual(merged[0]["license"], "MIT")
                self.assertEqual(merged[0]["license_source"], CDXGEN)
                self.assertEqual(merged[0]["license_declared"], "MIT")

    def _generate(self, repo, metadata, crates_cache):
        """Run the generator on one repository and return SPDX and CycloneDX."""
        with tempfile.TemporaryDirectory() as tmp:
            files = {
                "--input": {
                    "config": {"component_name": "app"},
                    "external_repos": [repo],
                },
                "--metadata": metadata,
                "--crates-cache": crates_cache,
            }
            argv = ["sbom_generator.py"]
            for flag, content in files.items():
                path = Path(tmp, flag.strip("-"))
                path.write_text(json.dumps(content))
                argv += [flag, str(path)]
            spdx_path, cdx_path = Path(tmp, "spdx"), Path(tmp, "cdx")
            argv += [
                "--spdx-output",
                str(spdx_path),
                "--cyclonedx-output",
                str(cdx_path),
            ]
            with mock.patch("sys.argv", argv):
                self.assertEqual(main(), 0)
            return json.loads(spdx_path.read_text()), json.loads(cdx_path.read_text())

    def test_generator_reports_both_licenses_from_the_crate_cache(self):
        repo = "rules_rust++crate+crate_index__serde-1.0.228"
        entry = {
            "name": "serde",
            "version": "1.0.228",
            "license": "MIT",
            "license_source": "external/serde/Cargo.toml",
            "license_concluded": "Apache-2.0",
        }
        spdx, cdx = self._generate(repo, {}, {"repo:" + repo: entry})
        serde = next(p for p in spdx["packages"] if p["name"] == "serde")
        self.assertEqual(serde["licenseDeclared"], "MIT")
        self.assertEqual(serde["licenseConcluded"], "Apache-2.0")
        self.assertIn(
            "differs from the license declared in Cargo.toml", serde["licenseComments"]
        )
        self.assertEqual(
            cdx["components"][0]["licenses"][0]["license"]["id"], "Apache-2.0"
        )

    def test_annotation_keeps_the_declaration_of_a_bare_name_cache_entry(self):
        annotation = {"version": "unknown", "purl_explicit": False}
        entry = {
            "name": "foo",
            "version": "1.0.0",
            "license": "MIT",
            "license_source": "external/foo/Cargo.toml",
        }
        spdx, _ = self._generate(
            "rules_rust++crate+crate_index__foo-1.0.0",
            {"crates": {"foo": {**annotation, "license": "Apache-2.0"}}},
            {"foo": entry},
        )
        foo = next(p for p in spdx["packages"] if p["name"] == "foo")
        self.assertEqual(foo["licenseDeclared"], "MIT")
        self.assertEqual(foo["licenseConcluded"], "Apache-2.0")
        self.assertIn("sbom_ext metadata", foo["licenseComments"])


if __name__ == "__main__":
    unittest.main()
