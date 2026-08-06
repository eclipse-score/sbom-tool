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

"""End-to-end checks on the SBOMs generated for the dummy project.

The unit tests in //tests exercise the generator's Python internals against
fixtures. This test instead runs against the artifacts of a real Bazel build, so
it catches breakage in the aspect, the rule and the module extension - the parts
no fixture can cover.
"""

import json
import pathlib
import unittest

# Bazel does not guarantee a working directory, so the SBOMs are located
# relative to this file: both land in the same runfiles package.
_HERE = pathlib.Path(__file__).parent
SPDX_PATH = _HERE / "dummy_sbom.spdx.json"
CDX_PATH = _HERE / "dummy_sbom.cdx.json"

# One dependency per language, to prove both toolchain paths were traversed.
CPP_DEPENDENCY = "nlohmann_json"
RUST_DEPENDENCY = "serde"


class SpdxOutputTest(unittest.TestCase):
    """The SPDX 2.3 document must be well-formed and describe the project."""

    @classmethod
    def setUpClass(cls):
        cls.doc = json.loads(SPDX_PATH.read_text(encoding="utf-8"))

    def test_document_header(self):
        self.assertEqual(self.doc["spdxVersion"], "SPDX-2.3")
        self.assertEqual(self.doc["dataLicense"], "CC0-1.0")
        self.assertEqual(self.doc["SPDXID"], "SPDXRef-DOCUMENT")
        self.assertTrue(self.doc["documentNamespace"])

    def test_creation_info_is_populated(self):
        creation_info = self.doc["creationInfo"]
        self.assertTrue(creation_info["created"])
        self.assertTrue(creation_info["creators"])

    def test_root_package_is_the_dummy_project(self):
        packages = {p["name"]: p for p in self.doc["packages"]}
        self.assertIn("score_sbom_dummy_project", packages)
        self.assertEqual(packages["score_sbom_dummy_project"]["versionInfo"], "0.1.0")

    def test_both_language_dependencies_are_present(self):
        names = {p["name"] for p in self.doc["packages"]}
        self.assertIn(CPP_DEPENDENCY, names)
        self.assertIn(RUST_DEPENDENCY, names)

    def test_every_package_has_an_spdxid_and_license_fields(self):
        for package in self.doc["packages"]:
            with self.subTest(package=package["name"]):
                self.assertTrue(package["SPDXID"].startswith("SPDXRef-"))
                self.assertIn("licenseConcluded", package)
                self.assertIn("licenseDeclared", package)

    def test_relationships_reference_known_spdxids(self):
        known = {p["SPDXID"] for p in self.doc["packages"]}
        known.add("SPDXRef-DOCUMENT")
        for relationship in self.doc["relationships"]:
            with self.subTest(relationship=relationship):
                self.assertIn(relationship["spdxElementId"], known)
                self.assertIn(relationship["relatedSpdxElement"], known)

    def test_document_describes_something(self):
        described = [
            r for r in self.doc["relationships"] if r["relationshipType"] == "DESCRIBES"
        ]
        self.assertTrue(described)


class CycloneDxOutputTest(unittest.TestCase):
    """The CycloneDX 1.6 document must be well-formed and describe the project."""

    @classmethod
    def setUpClass(cls):
        cls.doc = json.loads(CDX_PATH.read_text(encoding="utf-8"))

    def test_document_header(self):
        self.assertEqual(self.doc["bomFormat"], "CycloneDX")
        self.assertEqual(self.doc["specVersion"], "1.6")
        self.assertTrue(self.doc["serialNumber"].startswith("urn:uuid:"))

    def test_metadata_component_is_the_dummy_project(self):
        component = self.doc["metadata"]["component"]
        self.assertEqual(component["name"], "score_sbom_dummy_project")
        self.assertEqual(component["version"], "0.1.0")

    def test_both_language_dependencies_are_present(self):
        names = {c["name"] for c in self.doc["components"]}
        self.assertIn(CPP_DEPENDENCY, names)
        self.assertIn(RUST_DEPENDENCY, names)

    def test_bom_refs_are_unique(self):
        refs = [c["bom-ref"] for c in self.doc["components"]]
        self.assertCountEqual(refs, set(refs))

    def test_dependency_graph_has_no_dangling_refs(self):
        known = {c["bom-ref"] for c in self.doc["components"]}
        known.add(self.doc["metadata"]["component"]["bom-ref"])
        for entry in self.doc.get("dependencies", []):
            with self.subTest(ref=entry["ref"]):
                self.assertIn(entry["ref"], known)
                for dependency in entry.get("dependsOn", []):
                    self.assertIn(dependency, known)


class CrossFormatTest(unittest.TestCase):
    """Both documents are generated from one build and must agree."""

    @classmethod
    def setUpClass(cls):
        cls.spdx = json.loads(SPDX_PATH.read_text(encoding="utf-8"))
        cls.cdx = json.loads(CDX_PATH.read_text(encoding="utf-8"))

    def test_component_sets_match(self):
        # SPDX carries the root component as a package, CycloneDX keeps it in
        # metadata.component instead, so it is excluded from the comparison.
        root = self.cdx["metadata"]["component"]["name"]
        spdx_names = {p["name"] for p in self.spdx["packages"]} - {root}
        cdx_names = {c["name"] for c in self.cdx["components"]}
        self.assertEqual(spdx_names, cdx_names)


if __name__ == "__main__":
    unittest.main()
