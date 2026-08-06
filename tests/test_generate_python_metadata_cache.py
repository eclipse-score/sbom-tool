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

import os
import tempfile
import unittest

from scripts.generate_python_metadata_cache import (
    parse_dash_summary,
    parse_requirements_lockfile,
)


class TestParseRequirementsLockfile(unittest.TestCase):
    def test_pinned_packages_and_hashes(self):
        fd, path = tempfile.mkstemp(text=True)
        try:
            with os.fdopen(fd, "w") as lockfile:
                lockfile.write(
                    "requests==2.32.3 \\\n    --hash=sha256=" + "a" * 64 + "\n"
                )
                lockfile.write("typing_extensions==4.12.2\n")
            result = parse_requirements_lockfile(path)
        finally:
            os.unlink(path)

        self.assertEqual(result["requests"]["version"], "2.32.3")
        self.assertEqual(result["requests"]["checksum"], "a" * 64)
        self.assertEqual(result["requests"]["purl"], "pkg:pypi/requests@2.32.3")
        self.assertEqual(result["typing-extensions"]["license"], "NOASSERTION")

    def test_extras_are_normalized(self):
        fd, path = tempfile.mkstemp(text=True)
        try:
            with os.fdopen(fd, "w") as lockfile:
                lockfile.write("uv[standard]==0.8.9\n")
            result = parse_requirements_lockfile(path)
        finally:
            os.unlink(path)

        self.assertIn("uv", result)


class TestParseDashSummary(unittest.TestCase):
    def test_parses_python_purl_license_rows(self):
        fd, path = tempfile.mkstemp(text=True)
        try:
            with os.fdopen(fd, "w") as summary:
                summary.write("pypi/pypi/-/mdurl/0.1.2, MIT, approved, Eclipse\n")
                summary.write("not-a-pypi-row, Apache-2.0, approved, Eclipse\n")
            result = parse_dash_summary(path)
        finally:
            os.unlink(path)

        self.assertEqual(result, {"mdurl": "MIT"})
