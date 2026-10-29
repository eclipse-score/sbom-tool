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

"""Regression coverage for Git module overrides and Git-sourced Rust crates."""

import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from internal.generator.source_identity import git_identity
from internal.generator.source_metadata import (
    REGISTRY_SOURCES,
    parse_module_bazel_lock,
    parse_module_bazel_locks,
    read_module_lockfiles,
)
from internal.generator.sbom_generator import (
    main,
    parse_module_lockfiles,
    resolve_component,
    enrich_components_from_cpp_cache,
    deduplicate_components,
    mark_missing_cpp_descriptions,
)
from internal.generator.spdx_formatter import generate_spdx
from internal.generator.cyclonedx_formatter import generate_cyclonedx
from scripts.generate_crates_metadata_cache import generate_cache

SHA = "9f5622f554de48a7a296e1a5a71200b01e35a502"
REMOTE = "https://github.com/qorix-group/iceoryx2.git"
CRATE = "iceoryx2-bb-lock-free-qnx8"
REPO = "rules_rust++crate+crate_index__" + CRATE + "-0.7.0"
EXTENSION = "@@rules_rust+//crate_universe:extensions.bzl%crate"


def lockfile(attrs, extension=EXTENSION, variant="general"):
    return {
        "moduleExtensions": {
            extension: {
                variant: {
                    "generatedRepoSpecs": {
                        "crate_index__" + CRATE + "-0.7.0": {"attributes": attrs}
                    }
                }
            }
        }
    }


class TestGitSources(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.attrs = {
            "remote": REMOTE,
            "commit": SHA,
            "strip_prefix": "iceoryx2-bb/lock-free",
            "patches": ["//patches:fix.patch"],
            "patch_args": ["-p1"],
        }

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value))
        return str(path)

    def test_module_declared_version_and_revision_precedence(self):
        for declared, expected in [
            ("1.2.3", "1.2.3"),
            ("0.0.0", SHA),
            ("", SHA),
            ("unknown", SHA),
        ]:
            with self.subTest(declared=declared):
                component = resolve_component(
                    "score_time+",
                    {
                        "modules": {
                            "score_time": {
                                "version": declared,
                                "license": "MIT",
                                "sha256": "stale",
                            }
                        },
                        "git_overrides": {
                            "score_time": {
                                "remote": "https://github.com/eclipse-score/time.git",
                                "commit": SHA,
                            }
                        },
                    },
                )
                self.assertEqual(component["version"], expected)
                self.assertEqual(component["license"], "MIT")
                self.assertNotIn("checksum", component)
                self.assertEqual(
                    component["purl"], f"pkg:github/eclipse-score/time@{SHA}"
                )
                self.assertIn(SHA, component["source_info"])
                self.assertEqual(
                    component["url"], "https://github.com/eclipse-score/time.git"
                )
        tagged = git_identity("0.0.0", {**self.attrs, "tag": "release/1.2"})
        self.assertEqual(tagged["version"], "release/1.2")
        self.assertIn("@" + SHA + "#", tagged["purl"])
        self.assertNotIn("?", tagged["purl"])
        self.assertIn(SHA, tagged["source_info"])

    def test_git_repository_does_not_keep_short_sha_or_date(self):
        component = resolve_component(
            "lib+",
            {
                "git_repositories": {
                    "lib": {
                        "version": SHA[:12],
                        "commit": SHA,
                        "commit_date": "2026-01-01",
                        "remote": REMOTE,
                    }
                }
            },
        )
        self.assertEqual(component["version"], SHA)
        self.assertIn(SHA, component["purl"])

    def test_explicit_purl_annotation_is_preserved(self):
        purl = "pkg:generic/custom-lib@1.2.3"
        component = resolve_component(
            "lib+",
            {
                "git_repositories": {
                    "lib": {
                        "version": "1.2.3",
                        "remote": REMOTE,
                        "purl": purl,
                        "purl_explicit": True,
                    }
                }
            },
        )
        self.assertEqual(component["purl"], purl)
        self.assertEqual(component["url"], REMOTE)
        self.assertEqual(component["source"], "git")

        crate = {"version": "1.2.3", "purl": purl}
        component = resolve_component("lib", {"crates": {"lib": crate}})
        self.assertEqual(component["purl"], purl)
        component = resolve_component(
            "lib", {"crates": {"lib": {**crate, "remote": REMOTE, "commit": SHA}}}
        )
        self.assertEqual(component["purl"], "pkg:github/qorix-group/iceoryx2@" + SHA)
        self.assertIn(SHA, component["source_info"])
        self.assertEqual(component["url"], REMOTE)

    def test_remote_uri_and_subdirectory_encoding(self):
        for remote, prefix in [
            ("git@github.com:owner/repo.name.git", "pkg:github/owner/repo.name@"),
            ("ssh://git@gitlab.com/group/sub/repo.git", "pkg:gitlab/group/sub/repo@"),
            (
                "https://git.example.com/a/repo.git",
                "pkg:generic/git.example.com/a/repo@",
            ),
        ]:
            with self.subTest(remote=remote):
                result = git_identity("1.0", {**self.attrs, "remote": remote})
                self.assertTrue(result["purl"].startswith(prefix))
                self.assertEqual(urlsplit(result["purl"]).query, "")
                self.assertIn(SHA, result["source_info"])
                self.assertEqual(
                    urlsplit(result["purl"]).fragment, "iceoryx2-bb/lock-free"
                )

    def test_all_extensions_and_platforms_and_conflicts(self):
        data = lockfile(self.attrs)
        data["moduleExtensions"].update(
            lockfile(self.attrs, "@@other+//:crates.bzl%crate", "linux")[
                "moduleExtensions"
            ]
        )
        path = self.write("lock.json", data)
        entries = parse_module_bazel_lock(path)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[REPO]["source"], "git")
        self.assertEqual(entries[REPO]["commit"], SHA)
        data["moduleExtensions"][EXTENSION]["windows"] = lockfile(
            {**self.attrs, "commit": "a" * 40}
        )["moduleExtensions"][EXTENSION]["general"]
        with self.assertRaisesRegex(ValueError, "Conflicting crate sources"):
            parse_module_bazel_lock(self.write("lock.json", data))

    def test_git_crate_cache_preserves_source_and_manifest_license(self):
        manifest = self.root / "Cargo.toml"
        manifest.write_text(
            '[package]\nname="' + CRATE + '"\nversion="0.7.0"\nlicense="MIT"\n'
        )
        deps = self.write(
            "deps.json",
            {"external_repos": [REPO], "crate_manifests": {REPO: str(manifest)}},
        )
        with patch(
            "scripts.generate_crates_metadata_cache.fetch_crate_metadata_from_cratesio",
            return_value={},
        ) as api:
            cache = generate_cache(
                module_lock_paths=[self.write("lock.json", lockfile(self.attrs))],
                deps_path=deps,
            )
        entry = cache["repo:" + REPO]
        self.assertEqual(entry["license"], "MIT")
        self.assertEqual(entry["remote"], REMOTE)
        self.assertEqual(entry["commit"], SHA)
        self.assertEqual(entry["patches"], self.attrs["patches"])
        self.assertEqual(entry["purl"], "pkg:cargo/" + CRATE + "@0.7.0")
        self.assertEqual(api.call_args.kwargs["license_lookups"], set())

    def test_generator_git_crate_without_auto_cache_and_with_legacy_cache(self):
        for legacy in (False, True):
            with self.subTest(legacy_cache=legacy):
                locked = lockfile(self.attrs)
                locked["registryFileHashes"] = {
                    "https://bcr.bazel.build/modules/score_time/9.9.9/MODULE.bazel": "unused-candidate"
                }
                inputs = self.write(
                    "input.json",
                    {
                        "external_repos": ["score_time+", REPO],
                        "external_dep_edges": ["score_time+::" + REPO],
                        "module_lockfiles": [self.write("lock.json", locked)],
                        "config": {"component_name": "example"},
                    },
                )
                metadata = self.write(
                    "metadata.json",
                    {
                        "git_overrides": {
                            "score_time": {
                                "remote": "https://github.com/eclipse-score/time.git",
                                "commit": SHA,
                            }
                        }
                    },
                )
                spdx_path, cdx_path = self.root / "spdx.json", self.root / "cdx.json"
                argv = [
                    "sbom",
                    "--input",
                    inputs,
                    "--metadata",
                    metadata,
                    "--spdx-output",
                    str(spdx_path),
                    "--cyclonedx-output",
                    str(cdx_path),
                ]
                if legacy:
                    argv += [
                        "--crates-cache",
                        self.write(
                            "cache.json",
                            {
                                CRATE + "@0.7.0": {
                                    "version": "0.7.0",
                                    "license": "MIT",
                                    "checksum": "f" * 64,
                                    "purl": "pkg:cargo/" + CRATE + "@0.7.0",
                                }
                            },
                        ),
                    ]
                with patch("sys.argv", argv):
                    self.assertEqual(main(), 0)
                spdx = json.loads(spdx_path.read_text())
                module = next(p for p in spdx["packages"] if p["name"] == "score_time")
                self.assertEqual(module["versionInfo"], SHA)
                package = next(p for p in spdx["packages"] if p["name"] == CRATE)
                self.assertEqual(
                    package["downloadLocation"],
                    "git+" + REMOTE + "@" + SHA + "#iceoryx2-bb/lock-free",
                )
                self.assertEqual(package["versionInfo"], "0.7.0")
                self.assertNotIn("checksums", package)
                expected_purl = (
                    "pkg:github/qorix-group/iceoryx2@" + SHA + "#iceoryx2-bb/lock-free"
                )
                self.assertEqual(
                    package["externalRefs"][0]["referenceLocator"], expected_purl
                )
                self.assertIn(SHA, package["sourceInfo"])
                self.assertIn("//patches:fix.patch", package["sourceInfo"])
                self.assertTrue(
                    any(
                        r["relatedSpdxElement"] == package["SPDXID"]
                        and r["relationshipType"] == "DEPENDS_ON"
                        for r in spdx["relationships"]
                    )
                )
                cdx = json.loads(cdx_path.read_text())
                component = next(c for c in cdx["components"] if c["name"] == CRATE)
                self.assertEqual(component["purl"], expected_purl)
                self.assertEqual(
                    component["externalReferences"],
                    [{"type": "vcs", "url": package["downloadLocation"]}],
                )
                self.assertIn(SHA, component["pedigree"]["notes"])
                self.assertNotIn("crates.io", json.dumps(component))

    def test_registry_exact_version_is_recovered_without_license_cache(self):
        version = "0.11.1+wasi-snapshot-preview1"
        repository = "rules_rust++crate+crate_index__wasi-" + version.replace("+", "-")
        component = resolve_component(
            repository,
            {
                "crate_sources": {
                    repository: {
                        "version": version,
                        "version_from_repository": False,
                        "source": "registry+https://github.com/rust-lang/crates.io-index",
                        "checksum": "f" * 64,
                    }
                }
            },
        )
        self.assertEqual(component["version"], version)
        self.assertEqual(component["purl"], "pkg:cargo/wasi@" + version)
        self.assertEqual(component["url"], "https://crates.io/crates/wasi/" + version)
        self.assertEqual(component["checksum"], "f" * 64)

    def test_direct_crate_collector_cli(self):
        result = subprocess.run(
            [sys.executable, generate_cache.__code__.co_filename, "--help"],
            env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"},
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("--module-lock", result.stdout)

    def test_cpp_cache_cannot_invent_git_source_identity(self):
        component = {
            "name": "lib",
            **git_identity("unknown", {"remote": REMOTE}),
        }
        enriched = enrich_components_from_cpp_cache(
            [component],
            [
                {
                    "name": "lib",
                    "version": "1.2.3",
                    "checksum": "f" * 64,
                    "purl": "pkg:generic/lib@1.2.3",
                    "description": "Library",
                }
            ],
            {},
        )[0]
        self.assertEqual(enriched["version"], "unknown")
        self.assertFalse(enriched.get("checksum"))
        self.assertFalse(enriched["purl"])
        self.assertEqual(enriched["description"], "Library")

    def test_unknown_versions_and_locations_are_omitted(self):
        component = resolve_component("score_mystery+", {})
        spdx = generate_spdx([component], {}, "2026-01-01T00:00:00Z")
        package = spdx["packages"][1]
        self.assertNotIn("versionInfo", package)
        self.assertNotIn("externalRefs", package)
        self.assertEqual(package["downloadLocation"], "NOASSERTION")
        cdx = generate_cyclonedx([component], {}, "2026-01-01T00:00:00Z")["components"][
            0
        ]
        self.assertNotIn("version", cdx)
        self.assertNotIn("purl", cdx)

    def test_canonical_crate_name_precedes_cache_lookup(self):
        for name in ("lazy_static", "env_logger", "md-5"):
            repo = "rules_rust++crate+crate_index__" + name + "-0.10.6"
            cached = {"name": name, "version": "0.10.6", "license": "MIT"}
            for locked in (False, True):
                with self.subTest(name=name, locked=locked):
                    metadata = {"crates": {"repo:" + repo: cached}}
                    if locked:
                        metadata["crate_sources"] = {
                            repo: {**cached, "source": "crates.io"}
                        }
                    component = resolve_component(repo, metadata)
                    self.assertEqual(component["name"], name)
                    self.assertEqual(component["version"], "0.10.6")
                    self.assertEqual(component["license"], "MIT")
                    self.assertEqual(component["purl"], "pkg:cargo/" + name + "@0.10.6")

    def test_cpp_enrichment_fills_empty_purl(self):
        component = resolve_component("score_foo+", {})
        expected = "pkg:github/eclipse-score/foo@1.2.3"
        enrich_components_from_cpp_cache(
            [component],
            [{"name": "score_foo", "version": "1.2.3", "purl": expected}],
            {},
        )
        self.assertEqual(component["version"], "1.2.3")
        self.assertEqual(component["purl"], expected)

    def test_explicit_identifiers_survive_unknown_versions_and_git_sources(self):
        explicit = "pkg:github/acme/foo@abc123"
        component = resolve_component(
            "foo", {"http_archives": {"foo": {"purl": explicit}}}
        )
        for entry in (
            component,
            {"name": "foo", "version": "unknown", "purl": "pkg:generic/foo"},
        ):
            spdx = generate_spdx([entry], {}, "2026-01-01T00:00:00Z")["packages"][1]
            cdx = generate_cyclonedx([entry], {}, "2026-01-01T00:00:00Z")["components"][
                0
            ]
            self.assertNotIn("versionInfo", spdx)
            self.assertNotIn("version", cdx)
            self.assertEqual(spdx["externalRefs"][0]["referenceLocator"], entry["purl"])
            self.assertEqual(cdx["purl"], entry["purl"])
        for version in ("unknown", "0.7.0"):
            component = resolve_component(
                REPO,
                {
                    "crate_sources": {
                        REPO: {"name": CRATE, "version": "0.7.0", **self.attrs}
                    },
                    "crates": {
                        CRATE: {
                            "version": version,
                            "purl": explicit,
                            "purl_explicit": True,
                        }
                    },
                },
            )
            self.assertEqual(component["purl"], explicit)
        component = resolve_component(
            "foo",
            {
                "git_repositories": {
                    "foo": {"remote": REMOTE, "purl": explicit, "purl_explicit": True}
                }
            },
        )
        self.assertEqual(component["purl"], explicit)

    def test_partial_git_discovery_never_invents_a_revision(self):
        component = resolve_component(
            "foo+",
            {
                "modules": {"foo": {"version": "1.2.3", "sha256": "stale"}},
                "git_overrides": {
                    "foo": {"remote": REMOTE, "unresolved_fields": ["commit"]}
                },
            },
        )
        self.assertEqual(component["version"], "1.2.3")
        self.assertFalse(component["purl"])
        self.assertNotIn("checksum", component)
        self.assertIn("Unresolved Git attributes: commit", component["source_info"])
        spdx = generate_spdx([component], {}, "2026-01-01T00:00:00Z")["packages"][1]
        self.assertEqual(spdx["downloadLocation"], "NOASSERTION")

    def test_incomplete_discovery_preserves_unrelated_registry_modules(self):
        lock = self.write(
            "lock.json",
            {
                "registryFileHashes": {
                    "https://bcr.bazel.build/modules/zlib/1.3.1/source.json": "a" * 64,
                    "https://bcr.bazel.build/modules/gitlib/2.0.0/source.json": "b"
                    * 64,
                }
            },
        )
        inputs = self.write(
            "input.json",
            {
                "external_repos": ["zlib+", "gitlib+"],
                "module_lockfiles": [lock],
            },
        )
        metadata = self.write(
            "metadata.json",
            {
                "git_discovery_incomplete": True,
                "git_overrides": {"gitlib": {"remote": REMOTE, "commit": SHA}},
            },
        )
        output = self.root / "out.json"
        argv = [
            "sbom",
            "--input",
            inputs,
            "--metadata",
            metadata,
            "--spdx-output",
            str(output),
        ]
        with (
            patch("sys.argv", argv),
            patch("sys.stderr", new_callable=io.StringIO) as warnings,
        ):
            self.assertEqual(main(), 0)
        packages = {p["name"]: p for p in json.loads(output.read_text())["packages"]}
        self.assertEqual(packages["zlib"]["versionInfo"], "1.3.1")
        self.assertEqual(
            packages["zlib"]["externalRefs"][0]["referenceLocator"],
            "pkg:generic/zlib@1.3.1",
        )
        self.assertEqual(packages["gitlib"]["versionInfo"], SHA)
        self.assertIn("Git discovery is incomplete", warnings.getvalue())

    def test_legacy_crate_annotation_names_keep_canonical_identity(self):
        for name, alias in (("lazy_static", "lazy-static"), ("md-5", "md_5")):
            repo = "rules_rust++crate+crate_index__" + name + "-1.5.0"
            cached = {"name": name, "version": "1.5.0", "license": "MIT"}
            for version in ("unknown", "1.5.0", "2.0.0"):
                for explicit in (False, True):
                    with self.subTest(name=name, version=version, explicit=explicit):
                        annotation = {
                            "version": version,
                            "license": "Apache-2.0",
                            "cpe": "manual-cpe",
                            "purl_explicit": explicit,
                            "purl": "pkg:generic/annotated@1.5.0",
                        }
                        metadata = {
                            "crate_sources": {repo: cached},
                            "crates": {"repo:" + repo: cached, alias: annotation},
                        }
                        component = resolve_component(repo, metadata)
                        matches = version != "2.0.0"
                        self.assertEqual(component["name"], name)
                        self.assertEqual(component["version"], "1.5.0")
                        self.assertEqual(
                            component["license"], "Apache-2.0" if matches else "MIT"
                        )
                        self.assertEqual(
                            component.get("cpe"), "manual-cpe" if matches else None
                        )
                        self.assertEqual(
                            component["purl"],
                            annotation["purl"]
                            if matches and explicit
                            else "pkg:cargo/" + name + "@1.5.0",
                        )
                        metadata["crates"][name] = {
                            **annotation,
                            "version": "1.5.0",
                            "cpe": "exact-cpe",
                        }
                        self.assertEqual(
                            resolve_component(repo, metadata)["cpe"], "exact-cpe"
                        )

    def test_git_crates_are_not_marked_as_missing_cpp_descriptions(self):
        component = resolve_component(
            REPO,
            {
                "crate_sources": {
                    REPO: {"name": CRATE, "version": "0.7.0", **self.attrs}
                }
            },
        )
        cpp = {"name": "cpp", "type": "library"}
        mark_missing_cpp_descriptions([component, cpp])
        self.assertTrue(component["purl"].startswith("pkg:github/"))
        self.assertFalse(component.get("description"))
        self.assertEqual(cpp["description"], "Missing")

    def test_local_and_malformed_git_remotes_remain_provenance_only(self):
        for remote in (
            "/tmp/foo.git",
            "../foo.git",
            "file:///tmp/foo.git",
            "https:///foo.git",
            "https://[invalid",
        ):
            with self.subTest(remote=remote):
                component = {
                    "name": "foo",
                    **git_identity(
                        "1.2.3",
                        {
                            "remote": remote,
                            "commit": SHA,
                        },
                    ),
                }
                self.assertEqual(component["version"], "1.2.3")
                self.assertFalse(component["purl"])
                self.assertFalse(component["url"])
                self.assertIn(remote, component["source_info"])
                package = generate_spdx([component], {}, "2026-01-01T00:00:00Z")[
                    "packages"
                ][1]
                self.assertEqual(package["downloadLocation"], "NOASSERTION")
                self.assertNotIn("externalRefs", package)
                cdx = generate_cyclonedx([component], {}, "2026-01-01T00:00:00Z")[
                    "components"
                ][0]
                self.assertNotIn("purl", cdx)
                self.assertFalse(cdx.get("externalReferences"))

    def test_git_parent_does_not_supply_child_identity_or_provenance(self):
        for source in ("git_overrides", "git_repositories"):
            with self.subTest(source=source):
                metadata = {
                    "modules": {"boost": {"version": "1.87.0", "sha256": "stale"}},
                    source: {
                        "boost": {
                            **self.attrs,
                            "remote": "https://github.com/boostorg/boost.git",
                            "strip_prefix": "",
                        }
                    },
                }
                parent = resolve_component("boost+", metadata)
                children = [
                    resolve_component(name + "+", metadata)
                    for name in ("boost.config", "boost.assert")
                ]
                enrich_components_from_cpp_cache(children, [parent], metadata)
                for child in children:
                    self.assertEqual(child["version"], "unknown")
                    self.assertFalse(child["purl"])
                    for field in (
                        "source",
                        "source_info",
                        "checksum",
                        "download_location",
                    ):
                        self.assertNotIn(field, child)
                for formatter, key, id_key in (
                    (generate_spdx, "packages", "SPDXID"),
                    (generate_cyclonedx, "components", "bom-ref"),
                ):
                    entries = formatter(
                        [parent, *children], {}, "2026-01-01T00:00:00Z"
                    )[key]
                    self.assertEqual(
                        len({entry[id_key] for entry in entries}), len(entries)
                    )
                    for child in (
                        entry
                        for entry in entries
                        if entry["name"] in ("boost.config", "boost.assert")
                    ):
                        self.assertNotIn("purl", child)
                        self.assertNotIn("externalRefs", child)
                        self.assertNotIn("version", child)
                        self.assertNotIn("versionInfo", child)
                self.assertEqual(parent["purl"], "pkg:github/boostorg/boost@" + SHA)
                metadata["modules"]["boost.config"] = {
                    "version": "1.83.0",
                    "sha256": "registry",
                }
                independent = resolve_component("boost.config+", metadata)
                self.assertEqual(independent["purl"], "pkg:generic/boost.config@1.83.0")
                self.assertEqual(independent["checksum"], "registry")
                self.assertNotIn("source_info", independent)

    def test_identical_crates_in_two_hubs_merge_but_conflicts_fail(self):
        first_repo = REPO
        second_repo = REPO.replace("crate_index__", "crates__")
        registry = {
            "name": CRATE,
            "version": "0.7.0",
            "source": REGISTRY_SOURCES[0],
            "checksum": "a" * 64,
        }
        git = {"name": CRATE, "version": "0.7.0", **self.attrs}
        for info in (registry, git):
            with self.subTest(source=info):
                components = [
                    resolve_component(repo, {"crate_sources": {repo: info}})
                    for repo in (first_repo, second_repo)
                ]
                components[1]["description"] = "From second hub"
                merged = deduplicate_components(components)
                self.assertEqual(len(merged), 1)
                self.assertEqual(merged[0]["description"], "From second hub")
                changes = (
                    ({"checksum": "b" * 64}, {"patches": ["//:fix.patch"]})
                    if info == registry
                    else (
                        {"commit": "b" * 40},
                        {"strip_prefix": "other"},
                        {"patches": ["//:other.patch"]},
                    )
                )
                for change in changes:
                    different = resolve_component(
                        second_repo,
                        {"crate_sources": {second_repo: {**info, **change}}},
                    )
                    with self.assertRaisesRegex(
                        ValueError, "Conflicting crate repositories"
                    ):
                        deduplicate_components([components[0], different])

    def test_source_merge_keeps_nonempty_url_and_proven_registry(self):
        url = "https://static.crates.io/crates/" + CRATE + "/0.7.0/download"
        attrs = {"urls": [url], "sha256": "f" * 64, "strip_prefix": CRATE + "-0.7.0"}
        first = self.write("one.json", lockfile(attrs))
        second = self.write("two.json", lockfile({**attrs, "urls": []}))
        for paths in ([first, second], [second, first]):
            with self.subTest(paths=paths):
                merged = parse_module_bazel_locks(paths)[REPO]
                self.assertEqual(merged["source_url"], url)
                self.assertEqual(merged["source"], REGISTRY_SOURCES[0])
                self.assertEqual(merged["checksum"], attrs["sha256"])

    def test_equivalent_mirrors_merge_but_changed_contents_or_patches_fail(self):
        attrs = {
            "urls": ["https://static.crates.io/crates/" + CRATE + "/0.7.0/download"],
            "sha256": "f" * 64,
            "strip_prefix": CRATE + "-0.7.0",
        }
        first = lockfile(attrs)
        second = lockfile(
            {
                **attrs,
                "urls": [
                    "https://crates.io/api/v1/crates/" + CRATE + "/0.7.0/download"
                ],
                "patch_tool": "unused-tool",
            }
        )
        paths = [self.write("one.json", first), self.write("two.json", second)]
        self.assertEqual(len(parse_module_bazel_locks(paths)), 1)
        self.assertEqual(
            parse_module_bazel_locks(paths), parse_module_bazel_locks(paths[::-1])
        )
        first["moduleExtensions"][EXTENSION]["windows"] = second["moduleExtensions"][
            EXTENSION
        ]["general"]
        self.assertEqual(
            len(parse_module_bazel_lock(self.write("variants.json", first))), 1
        )
        for change in (
            {"sha256": "a" * 64},
            {"patches": ["//:fix.patch"]},
            {"patch_cmds": ["touch changed"]},
        ):
            with self.subTest(change=change):
                self.write("two.json", lockfile({**attrs, **change}))
                with self.assertRaisesRegex(ValueError, "Conflicting crate sources"):
                    parse_module_bazel_locks(paths)

    def test_empty_patch_defaults_do_not_create_conflicts(self):
        attrs = {**self.attrs, "patch_cmds": [], "patch_tool": "", "patch_strip": 0}
        first = self.write("one.json", lockfile(self.attrs))
        second = self.write("two.json", lockfile(attrs))
        self.assertEqual(len(parse_module_bazel_locks([first, second])), 1)
        attrs["patch_tool"] = "different-tool"
        self.write("two.json", lockfile(attrs))
        with self.assertRaisesRegex(ValueError, "Conflicting crate sources"):
            parse_module_bazel_locks([first, second])

    def test_bad_lockfiles_warn_and_shared_data_is_not_read_again(self):
        good = self.write("good.json", lockfile(self.attrs))
        bad = self.root / "bad.json"
        bad.write_text("{")
        paths = [good, str(bad), str(self.root / "missing.json"), good]
        with patch("sys.stderr", new_callable=io.StringIO) as warnings:
            lockfiles = read_module_lockfiles(paths)
        self.assertEqual(len(lockfiles), 1)
        self.assertEqual(warnings.getvalue().count("WARNING:"), 2)
        with patch(
            "builtins.open", side_effect=AssertionError("Unexpected second read")
        ):
            self.assertEqual(parse_module_lockfiles(paths, lockfiles=lockfiles), {})
            self.assertEqual(
                len(parse_module_bazel_locks(paths, lockfiles=lockfiles)), 1
            )

    def test_main_reads_each_lockfile_once(self):
        lock = self.write("lock.json", lockfile(self.attrs))
        inputs = self.write(
            "input.json", {"external_repos": [REPO], "module_lockfiles": [lock, lock]}
        )
        metadata = self.write("metadata.json", {})
        argv = [
            "sbom",
            "--input",
            inputs,
            "--metadata",
            metadata,
            "--spdx-output",
            str(self.root / "out.json"),
        ]
        with patch("sys.argv", argv), patch("builtins.open", wraps=open) as reads:
            self.assertEqual(main(), 0)
        self.assertEqual(sum(call.args[0] == lock for call in reads.call_args_list), 1)

    def test_archive_patches_keep_provenance_without_a_false_package_hash(self):
        attrs = {
            "urls": ["https://static.crates.io/crates/" + CRATE + "/0.7.0/download"],
            "sha256": "f" * 64,
            "patches": ["//patches:fix.patch"],
            "patch_cmds": ["touch modified"],
        }
        sources = parse_module_bazel_lock(self.write("patched.json", lockfile(attrs)))
        self.assertEqual(sources[REPO]["source"], "module-bazel-lock")
        component = resolve_component(REPO, {"crate_sources": sources})
        spdx = generate_spdx([component], {}, "2026-01-01T00:00:00Z")["packages"][1]
        cdx = generate_cyclonedx([component], {}, "2026-01-01T00:00:00Z")["components"][
            0
        ]
        self.assertNotIn("checksums", spdx)
        self.assertNotIn("hashes", cdx)
        for note in (spdx["sourceInfo"], cdx["pedigree"]["notes"]):
            self.assertIn("//patches:fix.patch", note)
            self.assertIn("touch modified", note)
            self.assertIn("SHA256 of unmodified source archive: " + "f" * 64, note)


if __name__ == "__main__":
    unittest.main()
