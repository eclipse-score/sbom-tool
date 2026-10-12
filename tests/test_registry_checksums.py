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

"""Check that package checksums use archive hashes, not metadata file hashes."""

import base64
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from internal.generator.registry_metadata import (
    archive_metadata,
    registry_source_hashes,
)
from internal.generator.sbom_generator import main, parse_module_lockfiles
from scripts.generate_registry_metadata_cache import generate_cache
from scripts.generate_registry_metadata_cache import main as cache_main


class TestRegistryChecksums(unittest.TestCase):
    URL = "https://bcr.bazel.build/modules/boost.config/1.83.0.bcr.4/source.json"
    METADATA_SHA = "0a5b5bf8d2afcf0731fcd452fe69f20d45b0d08ba07e70698cc7ee36f0ce7e9c"
    ARCHIVE_SHA = "b927c5e02c41aa833b7d5c4f9c09dd7668e7aff1086a5e3b6257d4e4825601b0"

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.source = (
            Path(__file__).parent / "fixtures/boost.config-1.83.0.bcr.4-source.json"
        ).read_text(encoding="utf-8")
        self.lock = self.write_json(
            "MODULE.bazel.lock", {"registryFileHashes": {self.URL: self.METADATA_SHA}}
        )

    def write_json(self, name, value):
        path = self.directory / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return str(path)

    def test_real_boost_metadata_identifies_archive(self):
        self.assertEqual(
            hashlib.sha256(self.source.encode()).hexdigest(), self.METADATA_SHA
        )
        result = parse_module_lockfiles([self.lock], {self.URL: self.source})[
            "boost.config"
        ]
        self.assertEqual(result["sha256"], self.ARCHIVE_SHA)
        self.assertEqual(result["url"], json.loads(self.source)["url"])
        self.assertNotEqual(result["sha256"], self.METADATA_SHA)

    def test_no_cache_never_emits_metadata_hash(self):
        result = parse_module_lockfiles([self.lock])["boost.config"]
        self.assertEqual(result["version"], "1.83.0.bcr.4")
        self.assertNotIn("sha256", result)

    def test_tampered_or_stale_cache_fails_verification(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            parse_module_lockfiles([self.lock], {self.URL: self.source + "\n"})

    def test_supplied_cache_requires_selected_sources(self):
        other_url = "https://bcr.bazel.build/modules/zlib/1.3.1/source.json"
        self.lock = self.write_json(
            "MODULE.bazel.lock",
            {"registryFileHashes": {self.URL: self.METADATA_SHA, other_url: "a" * 64}},
        )
        for entries, missing_url in (
            ({}, self.URL),
            ({"wrong-url": self.source}, self.URL),
            ({self.URL: self.source}, other_url),
        ):
            with self.subTest(entries=list(entries)):
                cache = self.write_json("cache.json", entries)
                with self.assertRaisesRegex(
                    ValueError, "missing selected source"
                ) as error:
                    self.generate(cache)
                self.assertIn(missing_url, str(error.exception))
                self.assertFalse((self.directory / "out.spdx.json").exists())
                self.assertFalse((self.directory / "out.cdx.json").exists())

    def test_supplied_cache_requires_json_object(self):
        for value in (None, [], "invalid", 42):
            with self.subTest(value=value):
                cache = self.write_json("cache.json", value)
                with self.assertRaisesRegex(ValueError, "must be a JSON object"):
                    self.generate(cache)
                self.assertFalse((self.directory / "out.spdx.json").exists())
                self.assertFalse((self.directory / "out.cdx.json").exists())

    def test_malformed_integrity_fails(self):
        for integrity in [
            "sha256-not!base64",
            "sha256-" + base64.b64encode(b"short").decode(),
        ]:
            with self.subTest(integrity=integrity):
                source = json.dumps(
                    {
                        "url": "https://example.org/archive.tar.gz",
                        "integrity": integrity,
                    }
                )
                with self.assertRaises(ValueError):
                    archive_metadata(
                        source, hashlib.sha256(source.encode()).hexdigest()
                    )

    def test_non_sha256_or_non_archive_source_has_no_archive_hash(self):
        for fields in [
            {"integrity": "sha512-" + base64.b64encode(b"x" * 64).decode()},
            {"type": "git_repository", "commit": "a" * 40},
            {"type": "local_path", "path": "/local/source"},
            {},
        ]:
            with self.subTest(fields=fields):
                source = json.dumps(
                    {"url": "https://example.org/archive.tar.gz", **fields}
                )
                expected = (
                    {"url": "https://example.org/archive.tar.gz"}
                    if fields.get("type", "archive") == "archive"
                    else {}
                )
                self.assertEqual(
                    archive_metadata(
                        source, hashlib.sha256(source.encode()).hexdigest()
                    ),
                    expected,
                )
                self.lock = self.write_json(
                    "MODULE.bazel.lock",
                    {
                        "registryFileHashes": {
                            self.URL: hashlib.sha256(source.encode()).hexdigest()
                        }
                    },
                )
                cache = self.write_json("cache.json", {self.URL: source})
                spdx, cdx = self.generate(
                    cache, {"modules": {"boost.config": {"version": "1.83.0.bcr.4"}}}
                )
                package = next(
                    p for p in spdx["packages"] if p["name"] == "boost.config"
                )
                component = next(
                    c for c in cdx["components"] if c["name"] == "boost.config"
                )
                self.assertNotIn("checksums", package)
                self.assertNotIn("hashes", component)
                self.assertEqual(
                    package["downloadLocation"], expected.get("url", "NOASSERTION")
                )
                self.assertEqual(
                    [
                        r["url"]
                        for r in component.get("externalReferences", [])
                        if r["type"] == "distribution"
                    ],
                    [expected["url"]] if expected else [],
                )

    def test_not_found_registry_entries_are_ignored(self):
        lock = self.write_json(
            "missing.lock", {"registryFileHashes": {self.URL: "not found"}}
        )
        self.assertEqual(registry_source_hashes([lock]), {})
        self.assertEqual(parse_module_lockfiles([lock]), {})

    def test_conflicting_lockfile_hashes_fail(self):
        lock = self.write_json(
            "other.lock", {"registryFileHashes": {self.URL: "a" * 64}}
        )
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            registry_source_hashes([self.lock, lock])
        with self.assertRaisesRegex(ValueError, "does not match"):
            parse_module_lockfiles([self.lock, lock], {self.URL: self.source})

    def test_conflicting_registry_source_types_fail(self):
        urls = [
            f"https://registry-{i}.example/modules/boost.config/1.83.0.bcr.4/source.json"
            for i in range(2)
        ]
        for fields in (
            {"type": "git_repository", "commit": "a" * 40},
            {"integrity": "sha512-" + base64.b64encode(b"x" * 64).decode()},
        ):
            source = json.dumps({"url": "https://example.org/archive.tar.gz", **fields})
            for sources in ((source, self.source), (self.source, source)):
                with self.subTest(
                    fields=fields, archive_first=sources[0] == self.source
                ):
                    cache = dict(zip(urls, sources))
                    locks = [
                        self.write_json(
                            f"{i}.lock",
                            {
                                "registryFileHashes": {
                                    url: hashlib.sha256(text.encode()).hexdigest()
                                }
                            },
                        )
                        for i, (url, text) in enumerate(cache.items())
                    ]
                    with self.assertRaisesRegex(
                        ValueError, "Conflicting archive metadata"
                    ):
                        parse_module_lockfiles(locks, cache)

    def test_cache_collector_preserves_verified_bytes(self):
        with patch(
            "urllib.request.urlopen", return_value=io.BytesIO(self.source.encode())
        ) as fetch:
            cache = generate_cache([self.lock, self.lock])
        self.assertEqual(cache, {self.URL: self.source})
        fetch.assert_called_once_with(self.URL, timeout=30)

    def test_cache_collector_rejects_changed_registry_file(self):
        with patch("urllib.request.urlopen", return_value=io.BytesIO(b"{}")):
            with self.assertRaisesRegex(ValueError, "does not match"):
                generate_cache([self.lock])

    def test_download_failure_does_not_write_successful_cache(self):
        output = self.directory / "cache.json"
        with (
            patch("sys.argv", ["cache", str(output), "--module-lock", self.lock]),
            patch(
                "urllib.request.urlopen", side_effect=urllib.error.URLError("offline")
            ),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            self.assertEqual(cache_main(), 1)
        self.assertFalse(output.exists())

    def test_both_formats_emit_archive_hash_and_location(self):
        cache_path = self.directory / "cache.json"
        with (
            patch("sys.argv", ["cache", str(cache_path), "--module-lock", self.lock]),
            patch(
                "urllib.request.urlopen", return_value=io.BytesIO(self.source.encode())
            ),
        ):
            self.assertEqual(cache_main(), 0)
        spdx, cdx = self.generate(str(cache_path))
        package = next(p for p in spdx["packages"] if p["name"] == "boost.config")
        component = next(c for c in cdx["components"] if c["name"] == "boost.config")
        self.assertEqual(
            package["checksums"],
            [{"algorithm": "SHA256", "checksumValue": self.ARCHIVE_SHA}],
        )
        self.assertEqual(package["downloadLocation"], json.loads(self.source)["url"])
        self.assertEqual(
            component["hashes"], [{"alg": "SHA-256", "content": self.ARCHIVE_SHA}]
        )

    def test_resolved_version_does_not_receive_other_versions_hash_or_url(self):
        cache = self.write_json("cache.json", {self.URL: self.source})
        spdx, cdx = self.generate(
            cache, {"modules": {"boost.config": {"version": "1.87.0"}}}
        )
        package = next(p for p in spdx["packages"] if p["name"] == "boost.config")
        self.assertEqual(package["versionInfo"], "1.87.0")
        self.assertNotIn("checksums", package)
        self.assertEqual(package["downloadLocation"], "NOASSERTION")
        component = next(c for c in cdx["components"] if c["name"] == "boost.config")
        self.assertNotIn("hashes", component)
        self.assertNotIn("externalReferences", component)

    def generate(self, cache, metadata=None):
        input_path = self.write_json(
            "input.json",
            {
                "external_repos": ["boost.config+"],
                "module_lockfiles": [self.lock],
                "config": {"component_name": "example"},
            },
        )
        metadata_path = self.write_json("metadata.json", metadata or {})
        spdx_path = self.directory / "out.spdx.json"
        cdx_path = self.directory / "out.cdx.json"
        with patch(
            "sys.argv",
            [
                "generator",
                "--input",
                input_path,
                "--metadata",
                metadata_path,
                "--registry-cache",
                cache,
                "--spdx-output",
                str(spdx_path),
                "--cyclonedx-output",
                str(cdx_path),
            ],
        ):
            self.assertEqual(main(), 0)
        return json.loads(spdx_path.read_text()), json.loads(cdx_path.read_text())
