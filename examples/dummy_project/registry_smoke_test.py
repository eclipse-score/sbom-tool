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

"""Test registry downloads and archive checksums through the Bazel rule."""

import json
from pathlib import Path
import unittest


class RegistryArchiveChecksumTest(unittest.TestCase):
    def test_nlohmann_archive_identity_in_both_formats(self):
        # SHA-256 of include.zip, taken from the registry's source.json.
        expected = "b8cb0ef2dd7f57f18933997c9934bb1fa962594f701cd5a8d3c2c80541559372"
        archive_url = (
            "https://github.com/nlohmann/json/releases/download/v3.12.0/include.zip"
        )
        here = Path(__file__).parent
        spdx = json.loads((here / "dummy_sbom_registry_smoke.spdx.json").read_text())
        cdx = json.loads((here / "dummy_sbom_registry_smoke.cdx.json").read_text())
        package = next(p for p in spdx["packages"] if p["name"] == "nlohmann_json")
        component = next(c for c in cdx["components"] if c["name"] == "nlohmann_json")
        self.assertEqual(package["versionInfo"], "3.12.0")
        self.assertEqual(
            package["checksums"], [{"algorithm": "SHA256", "checksumValue": expected}]
        )
        self.assertEqual(package["downloadLocation"], archive_url)
        self.assertEqual(component["hashes"], [{"alg": "SHA-256", "content": expected}])


if __name__ == "__main__":
    unittest.main()
