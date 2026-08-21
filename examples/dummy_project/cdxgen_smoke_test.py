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

"""Opt-in smoke test for the auto_cdxgen Node-toolchain execution path.

Not part of the default `bazel test //...` run (see BUILD.bazel "manual" tag):
it needs real network access to resolve the Bazel-managed Node toolchain and
to `npm exec` the pinned cdxgen package. dummy_sbom/sbom_test.py cover the
rest of the rule with auto_cdxgen off; this test exists so a regression in the
Node toolchain wiring (wrong executable, missing env, etc.) makes the build
fail instead of silently going untested, since the CdxgenGenerate action's
output is an input to the final SbomGenerate action tested here.
"""

import json
import pathlib
import unittest

_HERE = pathlib.Path(__file__).parent
CDX_PATH = _HERE / "dummy_sbom_cdxgen_smoke.cdx.json"


class CdxgenNodeToolchainTest(unittest.TestCase):
    """The final CycloneDX output must be well-formed after a real cdxgen run."""

    @classmethod
    def setUpClass(cls):
        cls.doc = json.loads(CDX_PATH.read_text(encoding="utf-8"))

    def test_document_header(self):
        self.assertEqual(self.doc["bomFormat"], "CycloneDX")
        self.assertIn("specVersion", self.doc)

    def test_components_field_present(self):
        # cdxgen's scan accuracy depends on host tooling (e.g. Java for atom
        # slicing) that isn't guaranteed here; this only asserts that the
        # Node-toolchain-driven cdxgen invocation itself succeeded and fed
        # valid data into the generator, not that it found every dependency.
        self.assertIn("components", self.doc)
        self.assertIsInstance(self.doc["components"], list)


if __name__ == "__main__":
    unittest.main()
