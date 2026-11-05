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
import itertools
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

from internal.generator.source_identity import (
    crate_source_identity,
    git_identity,
    git_url,
)
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
from scripts.generate_crates_metadata_cache import generate_cache, main as cache_main

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

    def test_git_module_versions_are_independent_of_metadata_path(self):
        for source, declared, revision in itertools.product(
            ("git_overrides", "git_repositories"),
            (None, "", "unknown", "0.0.0", "1.2.3"),
            ({"commit": SHA}, {"tag": "v2.0"}, {"commit": SHA, "tag": "v2.0"}),
        ):
            with self.subTest(source=source, declared=declared, revision=revision):
                metadata = {source: {"lib": {"remote": REMOTE, **revision}}}
                if declared is not None:
                    metadata["modules"] = {"lib": {"version": declared}}
                component = resolve_component("lib+", metadata)
                expected = declared if declared == "1.2.3" else revision.get("tag", SHA)
                self.assertEqual(component["version"], expected)
                self.assertEqual(
                    component["purl"],
                    "pkg:github/qorix-group/iceoryx2@" + revision.get("commit", "v2.0"),
                )
                spdx = generate_spdx([component], {}, "2026-01-01T00:00:00Z")[
                    "packages"
                ][1]
                cdx = generate_cyclonedx([component], {}, "2026-01-01T00:00:00Z")[
                    "components"
                ][0]
                self.assertEqual(spdx["versionInfo"], expected)
                self.assertEqual(cdx["version"], expected)

    def test_git_annotations_apply_from_all_extension_collections(self):
        explicit_purl = "pkg:generic/annotated@1.2.3"
        for source, collection, declared, explicit in itertools.product(
            ("git_overrides", "git_repositories"),
            ("licenses", "http_archives", "git_repositories"),
            (None, "1.2.3"),
            (False, True),
        ):
            with self.subTest(
                source=source,
                collection=collection,
                declared=declared,
                explicit=explicit,
            ):
                annotation = {
                    "version": "1.2.3",
                    "license": "MIT",
                    "supplier": "Annotated supplier",
                    "cpe": "explicit-cpe",
                    "aliases": ["alias"],
                    "pedigree_notes": "Annotated notes",
                    "purl": explicit_purl
                    if explicit
                    else (
                        ""
                        if collection == "licenses"
                        else "pkg:generic/generated@1.2.3"
                    ),
                    "purl_explicit": explicit,
                }
                metadata = {source: {"lib": {"remote": REMOTE, "commit": SHA}}}
                metadata.setdefault(collection, {}).setdefault("lib", {}).update(
                    annotation
                )
                if declared:
                    metadata["modules"] = {
                        "lib": {"version": declared, "license": "Apache-2.0"}
                    }
                component = resolve_component("lib+", metadata)
                for field in (
                    "license",
                    "supplier",
                    "cpe",
                    "aliases",
                    "pedigree_notes",
                ):
                    self.assertEqual(component[field], annotation[field])
                expected = (
                    explicit_purl
                    if explicit
                    else "pkg:github/qorix-group/iceoryx2@" + SHA
                )
                self.assertEqual(component["purl"], expected)
                self.assertEqual(
                    component["download_location"], "git+" + REMOTE + "@" + SHA
                )
                spdx = generate_spdx([component], {}, "2026-01-01T00:00:00Z")[
                    "packages"
                ][1]
                cdx = generate_cyclonedx([component], {}, "2026-01-01T00:00:00Z")[
                    "components"
                ][0]
                self.assertEqual(spdx["externalRefs"][0]["referenceLocator"], expected)
                self.assertEqual(cdx["purl"], expected)
                # A direct license annotation keeps priority over other tag types.
                metadata.setdefault("licenses", {})["lib"] = {
                    "license": "BSD-3-Clause",
                    "purl": "pkg:generic/direct@1.0",
                }
                component = resolve_component("lib+", metadata)
                self.assertEqual(component["license"], "BSD-3-Clause")
                self.assertEqual(component["purl"], "pkg:generic/direct@1.0")

    def test_lockfile_source_replaces_cached_source_in_both_directions(self):
        archive = {
            "source": REGISTRY_SOURCES[0],
            "source_url": "https://example.com/crate.tar.gz",
            "checksum": "a" * 64,
            "strip_prefix": CRATE + "-0.7.0",
        }
        sources = [
            archive,
            {**archive, "patches": ["//:archive.patch"]},
            self.attrs,
            {"remote": REMOTE, "tag": "v0.7.0"},
            {"source": "unknown"},
        ]
        for cached, locked, key in itertools.product(
            sources, sources, ("repo:" + REPO, CRATE + "@0.7.0")
        ):
            with self.subTest(cached=cached, locked=locked, key=key):
                metadata = {
                    "crate_sources": {
                        REPO: {"name": CRATE, "version": "0.7.0", **locked}
                    },
                    "crates": {
                        key: {
                            "name": CRATE,
                            "version": "0.7.0",
                            "license": "MIT",
                            "description": "Cached description",
                            **cached,
                        }
                    },
                }
                component = resolve_component(REPO, metadata)
                clean = resolve_component(
                    REPO, {"crate_sources": metadata["crate_sources"]}
                )
                for field in (
                    "source",
                    "url",
                    "purl",
                    "checksum",
                    "download_location",
                    "source_info",
                    "archive_source",
                    "git_commit",
                ):
                    self.assertEqual(
                        component.get(field) or "", clean.get(field) or "", field
                    )
                self.assertEqual(component["license"], "MIT")
                self.assertEqual(component["description"], "Cached description")
                clean.update(license="MIT", description="Cached description")
                for formatter, field in (
                    (generate_spdx, "packages"),
                    (generate_cyclonedx, "components"),
                ):
                    self.assertEqual(
                        formatter([component], {}, "2026-01-01T00:00:00Z")[field],
                        formatter([clean], {}, "2026-01-01T00:00:00Z")[field],
                    )

    def test_git_annotations_survive_without_a_module_entry(self):
        annotation = {
            "license": "MIT",
            "supplier": "Annotated supplier",
            "cpe": "cpe:2.3:a:example:library:*:*:*:*:*:*:*:*",
            "aliases": ["library-alias"],
            "pedigree_ancestors": ["pkg:generic/upstream@1.0"],
            "pedigree_descendants": ["pkg:generic/downstream@2.0"],
            "pedigree_variants": ["pkg:generic/variant@1.0"],
            "pedigree_notes": "Local annotation",
        }
        for source in ("git_overrides", "git_repositories"):
            for name in ("score_time", "other_lib"):
                for declared in (None, "1.2.3"):
                    for purl in ("", "pkg:generic/custom@1.0"):
                        with self.subTest(
                            source=source, name=name, declared=declared, purl=purl
                        ):
                            metadata = {
                                source: {name: self.attrs},
                                "licenses": {name: {**annotation, "purl": purl}},
                            }
                            if declared:
                                metadata["modules"] = {
                                    name: {"version": declared, "license": "Apache-2.0"}
                                }
                            before = copy.deepcopy(metadata)
                            component = resolve_component(name + "+", metadata)
                            self.assertEqual(metadata, before)
                            for field, value in annotation.items():
                                self.assertEqual(component[field], value)
                            expected = (
                                purl
                                or f"pkg:github/qorix-group/iceoryx2@{SHA}#iceoryx2-bb/lock-free"
                            )
                            self.assertEqual(component["purl"], expected)
                            self.assertIn(SHA, component["download_location"])
                            self.assertIn(
                                "//patches:fix.patch", component["source_info"]
                            )
                            spdx = generate_spdx(
                                [component], {}, "2026-01-01T00:00:00Z"
                            )["packages"][1]
                            cdx = generate_cyclonedx(
                                [component], {}, "2026-01-01T00:00:00Z"
                            )["components"][0]
                            self.assertEqual(spdx["licenseDeclared"], "MIT")
                            self.assertEqual(
                                spdx["supplier"], "Organization: Annotated supplier"
                            )
                            self.assertEqual(
                                cdx["licenses"], [{"license": {"id": "MIT"}}]
                            )
                            self.assertEqual(cdx["cpe"], annotation["cpe"])
                            self.assertIn(
                                annotation["pedigree_notes"], cdx["pedigree"]["notes"]
                            )

    def test_git_modules_do_not_inherit_same_named_crate_metadata(self):
        crate = {
            "version": "0.10.75",
            "license": "MIT",
            "description": "Rust bindings",
            "supplier": "Crate supplier",
            "purl": "pkg:cargo/openssl@0.10.75",
            "source": REGISTRY_SOURCES[0],
            "checksum": "a" * 64,
            "cpe": "crate-cpe",
            "aliases": ["crate-alias"],
        }
        for name, versioned, revision, annotated in itertools.product(
            ("openssl", "score_time"),
            (False, True),
            ({"commit": SHA}, {"tag": "v3.0"}, {"unresolved_fields": ["commit"]}),
            (False, True),
        ):
            with self.subTest(
                name=name, versioned=versioned, revision=revision, annotated=annotated
            ):
                metadata = {"git_overrides": {name: {"remote": REMOTE, **revision}}}
                if annotated:
                    metadata["licenses"] = {
                        name: {
                            "license": "BSD-3-Clause",
                            "supplier": "Module supplier",
                            "purl": "pkg:generic/custom@1.0",
                        }
                    }
                expected = resolve_component(name + "+", metadata)
                cache_key = name + "@0.10.75" if versioned else name
                with_cache = {**metadata, "crates": {cache_key: crate}}
                before = copy.deepcopy(with_cache)
                actual = resolve_component(name + "+", with_cache)
                self.assertEqual(actual, expected)
                self.assertEqual(with_cache, before)
                self.assertEqual(
                    actual["version"],
                    revision.get("tag", revision.get("commit", "unknown")),
                )
                self.assertNotIn("ecosystem", actual)
                # The unrelated Rust package must still resolve as a crate.
                rust = resolve_component(
                    "rules_rust++crate+crate_index__" + name + "-0.10.75", with_cache
                )
                self.assertEqual(rust["ecosystem"], "cargo")
                self.assertEqual(rust["version"], "0.10.75")
                self.assertEqual(rust["license"], "MIT")
                for formatter, field in (
                    (generate_spdx, "packages"),
                    (generate_cyclonedx, "components"),
                ):
                    self.assertEqual(
                        formatter([actual], {}, "2026-01-01T00:00:00Z")[field],
                        formatter([expected], {}, "2026-01-01T00:00:00Z")[field],
                    )

    def test_empty_git_annotations_keep_existing_metadata(self):
        component = resolve_component(
            "score_time+",
            {
                "git_overrides": {"score_time": self.attrs},
                "licenses": {
                    "score_time": {
                        "license": "",
                        "supplier": "",
                        "purl": "",
                        "aliases": [],
                    }
                },
            },
        )
        self.assertEqual(component["license"], "Apache-2.0")
        self.assertEqual(component["supplier"], "Eclipse Foundation")
        self.assertTrue(component["purl"].startswith("pkg:github/"))

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
                "pkg:generic/git.example.com/a/repo.git@",
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

    def test_scp_remotes_with_and_without_user_keep_source_identity(self):
        for authority, prefix in (
            ("github.com", "pkg:github/owner/repo@"),
            ("git@github.com", "pkg:github/owner/repo@"),
            ("gitlab.com", "pkg:gitlab/owner/repo@"),
            ("git@ssh-alias", "pkg:generic/ssh-alias/~git/owner/repo.git@"),
            ("ssh-alias", "pkg:generic/ssh-alias/~/owner/repo.git@"),
            ("[2001:db8::1]", "pkg:generic/2001%3Adb8%3A%3A1/~/owner/repo.git@"),
            ("git@[2001:db8::1]", "pkg:generic/2001%3Adb8%3A%3A1/~git/owner/repo.git@"),
        ):
            with self.subTest(authority=authority):
                component = {
                    "name": "lib",
                    **git_identity(
                        "1.0", {"remote": authority + ":owner/repo.git", "commit": SHA}
                    ),
                }
                path = (
                    "/owner/repo.git"
                    if prefix.startswith(("pkg:github/", "pkg:gitlab/"))
                    else "/~/owner/repo.git"
                )
                self.assertEqual(component["url"], "ssh://" + authority + path)
                self.assertEqual(component["purl"], prefix + SHA)
                spdx = generate_spdx([component], {}, "2026-01-01T00:00:00Z")[
                    "packages"
                ][1]
                cdx = generate_cyclonedx([component], {}, "2026-01-01T00:00:00Z")[
                    "components"
                ][0]
                location = "git+ssh://" + authority + path + "@" + SHA
                self.assertEqual(spdx["downloadLocation"], location)
                self.assertEqual(
                    cdx["externalReferences"], [{"type": "vcs", "url": location}]
                )

    def test_ssh_home_relative_paths_do_not_alias_absolute_paths_or_users(self):
        remotes = (
            (
                "git@build-host:repos/lib.git",
                "ssh://git@build-host/~/repos/lib.git",
                "~git/repos/lib.git",
            ),
            (
                "alice@build-host:repos/lib.git",
                "ssh://alice@build-host/~/repos/lib.git",
                "~alice/repos/lib.git",
            ),
            (
                "build-host:repos/lib.git",
                "ssh://build-host/~/repos/lib.git",
                "~/repos/lib.git",
            ),
            (
                "git@build-host:/repos/lib.git",
                "ssh://git@build-host/repos/lib.git",
                "repos/lib.git",
            ),
            (
                "git@build-host:~alice/repos/lib.git",
                "ssh://git@build-host/~alice/repos/lib.git",
                "~alice/repos/lib.git",
            ),
            (
                "git@build-host:repos/a #%.git",
                "ssh://git@build-host/~/repos/a%20%23%25.git",
                "~git/repos/a%20%23%25.git",
            ),
        )
        components = []
        for remote, url, path in remotes:
            with self.subTest(remote=remote):
                self.assertEqual(git_url(remote), url)
                component = git_identity("1.0", {"remote": remote, "commit": SHA})
                self.assertEqual(
                    component, git_identity("1.0", {"remote": url, "commit": SHA})
                )
                self.assertEqual(
                    component["purl"], f"pkg:generic/build-host/{path}@{SHA}"
                )
                self.assertEqual(component["download_location"], f"git+{url}@{SHA}")
                components.append(component)
        self.assertEqual(len({c["purl"] for c in components[:4]}), 4)
        for first, second in itertools.combinations(components[:4], 2):
            crates = [
                {
                    "name": CRATE,
                    "ecosystem": "cargo",
                    "bazel_repository": repo,
                    **component,
                }
                for repo, component in zip(
                    (REPO, REPO.replace("crate_index__", "crates__")), (first, second)
                )
            ]
            with self.assertRaisesRegex(ValueError, "Conflicting crate repositories"):
                deduplicate_components(crates)

    def test_git_ports_distinguish_repositories(self):
        for scheme, host in itertools.product(
            ("https", "http", "ssh", "git"),
            ("git.example.com", "github.com", "gitlab.com", "[2001:db8::1]"),
        ):
            identities = []
            for port in (8443, 9443):
                with self.subTest(scheme=scheme, host=host, port=port):
                    remote = f"{scheme}://{host}:{port}/team/lib.git"
                    component = {
                        "name": "lib",
                        **git_identity("1.0", {"remote": remote, "tag": "v1.0"}),
                    }
                    authority = (
                        host.replace("[", "%5B").replace("]", "%5D").replace(":", "%3A")
                    )
                    expected = f"pkg:generic/{authority}%3A{port}/team/lib.git@v1.0"
                    self.assertEqual(component["purl"], expected)
                    identities.append(component["purl"])
                    spdx = generate_spdx([component], {}, "2026-01-01T00:00:00Z")[
                        "packages"
                    ][1]
                    cdx = generate_cyclonedx([component], {}, "2026-01-01T00:00:00Z")[
                        "components"
                    ][0]
                    self.assertEqual(spdx["downloadLocation"], f"git+{remote}@v1.0")
                    self.assertEqual(
                        spdx["externalRefs"][0]["referenceLocator"], expected
                    )
                    self.assertEqual(cdx["purl"], expected)
            self.assertEqual(len(set(identities)), 2)
        for scheme, port in (("https", 443), ("http", 80), ("ssh", 22), ("git", 9418)):
            with self.subTest(scheme=scheme, default_port=port):
                for host in ("github.com", "gitlab.com"):
                    component = git_identity(
                        "1.0",
                        {
                            "remote": f"{scheme}://{host}:{port}/team/lib.git",
                            "tag": "v1.0",
                        },
                    )
                    self.assertEqual(
                        component["purl"], f"pkg:{host.split('.')[0]}/team/lib@v1.0"
                    )

    def test_git_suffix_is_only_removed_for_public_host_purls(self):
        for remote, aliases in (
            ("https://git.example/team/lib", False),
            ("https://git.example:443/team/lib", False),
            ("git@host:team/lib", False),
            ("ssh://git@host/~/team/lib", False),
            ("https://github.com:8443/team/lib", False),
            ("https://gitlab.com:8443/team/lib", False),
            ("https://github.com/team/lib", True),
            ("https://gitlab.com/team/lib", True),
            ("https://github.com:443/team/lib", True),
            ("ssh://git@github.com/team/lib", True),
        ):
            purls = []
            suffixes = ("", ".git", "%2Egit") if "://" in remote else ("", ".git")
            for suffix in suffixes:
                with self.subTest(remote=remote, suffix=suffix):
                    component = {
                        "name": "lib",
                        **git_identity(
                            "1.0",
                            {
                                "remote": remote + suffix,
                                "tag": "v1.0",
                                "strip_prefix": "src/lib",
                            },
                        ),
                    }
                    expected_suffix = ".git" if suffix and not aliases else ""
                    self.assertTrue(
                        component["purl"].endswith(
                            "/lib" + expected_suffix + "@v1.0#src/lib"
                        )
                    )
                    spdx = generate_spdx([component], {}, "2026-01-01T00:00:00Z")[
                        "packages"
                    ][1]
                    cdx = generate_cyclonedx([component], {}, "2026-01-01T00:00:00Z")[
                        "components"
                    ][0]
                    self.assertEqual(
                        spdx["externalRefs"][0]["referenceLocator"], component["purl"]
                    )
                    self.assertEqual(cdx["purl"], component["purl"])
                    purls.append(component["purl"])
            self.assertEqual(len(set(purls)), 1 if aliases else 2)

    def test_http_git_credentials_are_removed_from_all_reporting_fields(self):
        for scheme, userinfo, host, revision in itertools.product(
            ("http", "https", "git+https", "HTTPS"),
            ("test-login:test-secret", "test-token", "test-login:encoded%40secret"),
            (
                "git.example.com:8443",
                "[2001:db8::1]:8443",
                "git.example.com:bad",
                "[invalid",
            ),
            ({"commit": SHA}, {"unresolved_fields": ["commit"]}),
        ):
            with self.subTest(
                scheme=scheme, userinfo=userinfo, host=host, revision=revision
            ):
                public = f"{scheme}://{host}/team/lib.git"
                private = f"{scheme}://{userinfo}@{host}/team/lib.git"
                info = {"remote": private, **revision}
                before = copy.deepcopy(info)
                result = git_identity("1.0", info)
                public_result = git_identity("1.0", {**info, "remote": public})
                self.assertNotEqual(
                    result["source_fingerprint"], public_result["source_fingerprint"]
                )
                self.assertEqual(
                    {
                        key: value
                        for key, value in result.items()
                        if key != "source_fingerprint"
                    },
                    {
                        key: value
                        for key, value in public_result.items()
                        if key != "source_fingerprint"
                    },
                )
                self.assertEqual(info, before)
                component = {"name": "lib", **result}
                for report in (
                    result,
                    generate_spdx([component], {}, "2026-01-01T00:00:00Z"),
                    generate_cyclonedx([component], {}, "2026-01-01T00:00:00Z"),
                ):
                    self.assertNotIn(userinfo, json.dumps(report))
        # Lockfile and older Cargo/cache paths must use the same reporting rules.
        private = "https://test-login:test-secret@git.example.com/team/lib.git"
        for info in (
            {"remote": private, "commit": SHA},
            {"source": f"git+{private}?branch=main#{SHA}"},
        ):
            component = resolve_component(
                REPO,
                {
                    "crates": {
                        "repo:" + REPO: {"name": CRATE, "version": "0.7.0", **info}
                    }
                },
            )
            self.assertNotIn("test-secret", json.dumps(component))
            self.assertEqual(component["url"], "https://git.example.com/team/lib.git")
        ssh = git_identity(
            "1.0", {"remote": "test-login@build-host:repo.git", "commit": SHA}
        )
        self.assertEqual(ssh["url"], "ssh://test-login@build-host/~/repo.git")
        self.assertIn("/~test-login/", ssh["purl"])

    def test_git_download_revision_and_subdirectory_are_uri_encoded(self):
        for tag, encoded_tag in (
            ("release#1", "release%231"),
            ("release%231", "release%25231"),
            ("release@1", "release%401"),
            ("réléase/1+meta", "r%C3%A9l%C3%A9ase%2F1+meta"),
        ):
            for remote in (REMOTE, "ssh://git@build-host/~/lib.git"):
                for subpath, encoded_subpath in (
                    ("", ""),
                    ("crates/lib", "crates/lib"),
                    (
                        "crates/a #?%[]@+/子",
                        "crates/a%20%23%3F%25%5B%5D%40%2B/%E5%AD%90",
                    ),
                ):
                    with self.subTest(tag=tag, remote=remote, subpath=subpath):
                        component = {
                            "name": "lib",
                            **git_identity(
                                "1.0",
                                {"remote": remote, "tag": tag, "strip_prefix": subpath},
                            ),
                        }
                        expected = "git+" + remote + "@" + encoded_tag
                        if subpath:
                            expected += "#" + encoded_subpath
                        self.assertEqual(component["download_location"], expected)
                        self.assertTrue(
                            component["purl"].endswith(
                                "@"
                                + encoded_tag
                                + ("#" + encoded_subpath if subpath else "")
                            )
                        )
                        parsed = urlsplit(expected)
                        self.assertEqual(unquote(parsed.path.rsplit("@", 1)[1]), tag)
                        self.assertEqual(unquote(parsed.fragment), subpath)
                        self.assertEqual(parsed.query, "")
                        spdx = generate_spdx([component], {}, "2026-01-01T00:00:00Z")[
                            "packages"
                        ][1]
                        cdx = generate_cyclonedx(
                            [component], {}, "2026-01-01T00:00:00Z"
                        )["components"][0]
                        self.assertEqual(spdx["downloadLocation"], expected)
                        self.assertEqual(
                            cdx["externalReferences"],
                            [{"type": "vcs", "url": expected}],
                        )

    def test_submodule_checkout_modes_control_source_merging(self):
        settings = (
            ({}, "none"),
            ({"init_submodules": False}, "none"),
            ({"init_submodules": False, "recursive_init_submodules": False}, "none"),
            ({"init_submodules": True}, "direct"),
            ({"recursive_init_submodules": True}, "recursive"),
            (
                {"init_submodules": False, "recursive_init_submodules": True},
                "recursive",
            ),
            ({"init_submodules": True, "recursive_init_submodules": True}, "recursive"),
        )
        other_repo = REPO.replace("crate_index__", "crates__")
        for (left, left_mode), (right, right_mode) in itertools.product(
            settings, repeat=2
        ):
            with self.subTest(left=left, right=right):
                # No patches: checkout settings must survive patch-default cleanup.
                attrs = {"remote": REMOTE, "commit": SHA}
                first, second = (
                    lockfile({**attrs, **left}),
                    lockfile({**attrs, **right}),
                )
                paths = [
                    self.write("left.json", first),
                    self.write("right.json", second),
                ]
                variants = copy.deepcopy(first)
                variants["moduleExtensions"][EXTENSION]["other"] = second[
                    "moduleExtensions"
                ][EXTENSION]["general"]
                variant_path = self.write("variants.json", variants)
                components = [
                    resolve_component(
                        repo,
                        {"crate_sources": {repo: parse_module_bazel_lock(path)[REPO]}},
                    )
                    for repo, path in zip((REPO, other_repo), paths)
                ]
                if left_mode == right_mode:
                    self.assertEqual(len(parse_module_bazel_locks(paths)), 1)
                    self.assertEqual(len(parse_module_bazel_lock(variant_path)), 1)
                    self.assertEqual(len(deduplicate_components(components)), 1)
                else:
                    with self.assertRaisesRegex(
                        ValueError, "Conflicting crate sources"
                    ):
                        parse_module_bazel_locks(paths)
                    with self.assertRaisesRegex(
                        ValueError, "Conflicting crate sources"
                    ):
                        parse_module_bazel_lock(variant_path)
                    with self.assertRaisesRegex(
                        ValueError, "Conflicting crate repositories"
                    ):
                        deduplicate_components(components)

    def test_submodule_settings_survive_cache_and_both_formats(self):
        for settings, expected in (
            ({"init_submodules": False}, ""),
            ({"init_submodules": True}, "init_submodules: true"),
            ({"recursive_init_submodules": True}, "recursive_init_submodules: true"),
            (
                {"init_submodules": True, "recursive_init_submodules": True},
                "recursive_init_submodules: true",
            ),
        ):
            with self.subTest(settings=settings):
                attrs = {**self.attrs, **settings}
                path = self.write("lock.json", lockfile(attrs))
                deps = self.write("deps.json", {"external_repos": [REPO]})
                output = self.root / "cache.json"
                with (
                    patch(
                        "sys.argv",
                        [
                            "cache",
                            str(output),
                            "--module-lock",
                            path,
                            "--deps-json",
                            deps,
                        ],
                    ),
                    patch(
                        "scripts.generate_crates_metadata_cache.fetch_crate_metadata_from_cratesio",
                        return_value={},
                    ),
                    patch("sys.stdout", new_callable=io.StringIO),
                    patch("sys.stderr", new_callable=io.StringIO),
                ):
                    self.assertEqual(cache_main(), 0)
                cache = json.loads(output.read_text())
                for field, value in settings.items():
                    self.assertEqual(cache["repo:" + REPO][field], value)
                cached = resolve_component(REPO, {"crates": cache})
                locked = resolve_component(
                    REPO, {"crate_sources": parse_module_bazel_lock(path)}
                )
                module = git_identity("0.7.0", attrs)
                legacy = crate_source_identity(
                    CRATE,
                    "0.7.0",
                    {
                        **{k: v for k, v in attrs.items() if k != "remote"},
                        "source": f"git+{REMOTE}#{SHA}",
                    },
                )
                for component in (cached, locked, module, legacy):
                    self.assertEqual(component["source_info"], locked["source_info"])
                    if expected:
                        self.assertIn(expected, component["source_info"])
                    else:
                        self.assertNotIn("init_submodules", component["source_info"])
                spdx = generate_spdx([locked], {}, "2026-01-01T00:00:00Z")["packages"][
                    1
                ]
                cdx = generate_cyclonedx([locked], {}, "2026-01-01T00:00:00Z")[
                    "components"
                ][0]
                self.assertEqual(spdx["sourceInfo"], locked["source_info"])
                self.assertEqual(cdx["pedigree"]["notes"], locked["source_info"])

    def test_remote_patch_order_is_preserved_and_compared(self):
        patches = {
            "https://example.com/z-first.patch": "sha256-first",
            "https://example.com/a-second.patch": "sha256-second",
        }
        reversed_patches = dict(reversed(list(patches.items())))
        archive = {
            "urls": ["https://example.com/crate.tar.gz"],
            "sha256": "a" * 64,
            "strip_prefix": CRATE + "-0.7.0",
        }
        for attrs in (archive, self.attrs):
            for first_order, second_order in (
                (patches, reversed_patches),
                (reversed_patches, patches),
            ):
                with self.subTest(attrs=attrs, first_order=list(first_order)):
                    first = lockfile({**attrs, "remote_patches": first_order})
                    second = lockfile({**attrs, "remote_patches": second_order})
                    paths = [
                        self.write("one.json", first),
                        self.write("two.json", second),
                    ]
                    with self.assertRaisesRegex(
                        ValueError, "Conflicting crate sources"
                    ):
                        parse_module_bazel_locks(paths)
                    variants = copy.deepcopy(first)
                    variants["moduleExtensions"][EXTENSION]["other"] = second[
                        "moduleExtensions"
                    ][EXTENSION]["general"]
                    with self.assertRaisesRegex(
                        ValueError, "Conflicting crate sources"
                    ):
                        parse_module_bazel_lock(self.write("variants.json", variants))
                    sources = parse_module_bazel_lock(paths[0])
                    other_repo = REPO.replace("crate_index__", "crates__")
                    original = resolve_component(REPO, {"crate_sources": sources})
                    equal = resolve_component(
                        other_repo, {"crate_sources": {other_repo: sources[REPO]}}
                    )
                    self.assertEqual(len(deduplicate_components([original, equal])), 1)
                    different = resolve_component(
                        other_repo,
                        {
                            "crate_sources": {
                                other_repo: {
                                    **sources[REPO],
                                    "remote_patches": second_order,
                                }
                            }
                        },
                    )
                    with self.assertRaisesRegex(
                        ValueError, "Conflicting crate repositories"
                    ):
                        deduplicate_components([original, different])
                    spdx = generate_spdx([original], {}, "2026-01-01T00:00:00Z")[
                        "packages"
                    ][1]
                    cdx = generate_cyclonedx([original], {}, "2026-01-01T00:00:00Z")[
                        "components"
                    ][0]
                    for note in (spdx["sourceInfo"], cdx["pedigree"]["notes"]):
                        self.assertLess(
                            note.index(next(iter(first_order))),
                            note.index(list(first_order)[1]),
                        )

    def test_crate_cache_round_trip_preserves_remote_patch_order(self):
        patches = {
            "https://example.com/z-first.patch": "sha256-first",
            "https://example.com/a-second.patch": "sha256-second",
        }
        archive = {
            "urls": ["https://example.com/crate.tar.gz"],
            "sha256": "a" * 64,
            "strip_prefix": CRATE + "-0.7.0",
        }
        for attrs in (archive, self.attrs):
            with self.subTest(attrs=attrs):
                path = self.write(
                    "lock.json", lockfile({**attrs, "remote_patches": patches})
                )
                deps = self.write("deps.json", {"external_repos": [REPO]})
                output = self.root / "cache.json"
                with (
                    patch(
                        "sys.argv",
                        [
                            "cache",
                            str(output),
                            "--module-lock",
                            path,
                            "--deps-json",
                            deps,
                        ],
                    ),
                    patch(
                        "scripts.generate_crates_metadata_cache.fetch_crate_metadata_from_cratesio",
                        return_value={},
                    ),
                    patch("sys.stdout", new_callable=io.StringIO),
                    patch("sys.stderr", new_callable=io.StringIO),
                ):
                    self.assertEqual(cache_main(), 0)
                cache = json.loads(output.read_text())
                self.assertEqual(
                    list(cache["repo:" + REPO]["remote_patches"].items()),
                    list(patches.items()),
                )
                cached = resolve_component(REPO, {"crates": cache})
                locked = resolve_component(
                    REPO, {"crate_sources": parse_module_bazel_lock(path)}
                )
                self.assertEqual(cached["source_info"], locked["source_info"])
                self.assertEqual(cached["archive_source"], locked["archive_source"])

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

    def test_repository_cache_keeps_canonical_legacy_annotation_precedence(self):
        for name, alias in (("lazy_static", "lazy-static"), ("md-5", "md_5")):
            repo = "rules_rust++crate+crate_index__" + name + "-1.5.0"
            for marker in ({}, {"purl_explicit": False}):
                canonical = {
                    "version": "1.5.0",
                    "cpe": "cpe:2.3:a:example:canonical:1.5.0:*:*:*:*:*:*:*",
                    "aliases": ["canonical"],
                    "pedigree_notes": "Canonical annotation",
                    **marker,
                }
                legacy = {
                    **canonical,
                    "cpe": "cpe:2.3:a:example:legacy:1.5.0:*:*:*:*:*:*:*",
                    "aliases": ["legacy"],
                    "pedigree_notes": "Legacy annotation",
                }
                entries = [(name, canonical), (alias, legacy)]
                for ordered in (entries, list(reversed(entries))):
                    with self.subTest(
                        name=name, marker=marker, order=[key for key, _ in ordered]
                    ):
                        crates = dict(ordered)
                        baseline = resolve_component(repo, {"crates": crates})
                        crates["repo:" + repo] = {"name": name, "version": "1.5.0"}
                        cached = resolve_component(repo, {"crates": crates})
                        for field in ("cpe", "aliases", "pedigree_notes"):
                            self.assertEqual(baseline[field], canonical[field])
                            self.assertEqual(cached[field], canonical[field])
                        report = generate_cyclonedx(
                            [cached], {}, "2026-01-01T00:00:00Z"
                        )
                        self.assertEqual(
                            report["components"][0]["cpe"], canonical["cpe"]
                        )
                        self.assertNotIn(legacy["cpe"], json.dumps(report))

    def test_crate_annotations_respect_repository_scope(self):
        name, alias, version = "lazy_static", "lazy-static", "1.5.0"
        repo = "rules_rust++crate+crates__" + name + "-" + version
        other_repo = repo.replace("crates__", "crate_index__")
        source = {"name": name, "version": version, **self.attrs}
        fields = {
            "license": "MIT",
            "supplier": "Annotated supplier",
            "cpe": "cpe:2.3:a:example:fork:1.5.0:*:*:*:*:*:*:*",
            "aliases": ["fork-alias"],
            "pedigree_ancestors": ["pkg:generic/ancestor@1.0"],
            "pedigree_descendants": ["pkg:generic/descendant@2.0"],
            "pedigree_variants": ["pkg:generic/variant@1.0"],
            "pedigree_notes": "Fork annotation",
        }
        for key, scope, marker, cached in itertools.product(
            (name, alias, name + "@" + version, alias + "@" + version),
            (None, "", repo, other_repo),
            ({}, {"purl_explicit": False}, {"purl_explicit": True}),
            (False, True),
        ):
            with self.subTest(key=key, scope=scope, marker=marker, cached=cached):
                metadata = {"crate_sources": {repo: source}, "crates": {}}
                if cached:
                    metadata["crates"]["repo:" + repo] = source
                baseline = resolve_component(repo, metadata)
                annotation = {
                    "version": version,
                    "purl": "pkg:generic/annotated-fork@1.5.0",
                    **fields,
                    **marker,
                }
                if scope is not None:
                    annotation["bazel_repository"] = scope
                metadata["crates"][key] = annotation
                component = resolve_component(repo, metadata)
                if scope == other_repo:
                    self.assertEqual(component, baseline)
                else:
                    for field, value in fields.items():
                        self.assertEqual(component[field], value)
                    if marker.get("purl_explicit"):
                        self.assertEqual(component["purl"], annotation["purl"])
                for formatter, field in (
                    (generate_spdx, "packages"),
                    (generate_cyclonedx, "components"),
                ):
                    report = formatter([component], {}, "2026-01-01T00:00:00Z")
                    if scope == other_repo:
                        self.assertEqual(
                            report[field],
                            formatter([baseline], {}, "2026-01-01T00:00:00Z")[field],
                        )
                    elif field == "components":
                        self.assertIn(fields["cpe"], json.dumps(report))

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
            "./host:repo.git",
            "/tmp/host:repo.git",
            r"C:\repos\foo.git",
            "C:/repos/foo.git",
            r"C:relative\foo.git",
            r".\host:repo.git",
            "helper::address",
            "file:///tmp/foo.git",
            "https:///foo.git",
            "https://[invalid",
            "https://git.example.com:invalid/foo.git",
            "https://git.example.com:65536/foo.git",
            "https://git.example.com:-1/foo.git",
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
                    resolve_component(
                        repo,
                        {
                            "crate_sources": {repo: info},
                            "crates": {"repo:" + repo: registry},
                        },
                    )
                    for repo in (first_repo, second_repo)
                ]
                if info == git:
                    self.assertFalse(components[0].get("archive_source"))
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

    def test_git_hubs_require_full_commits_to_merge(self):
        other_repo = REPO.replace("crate_index__", "crates__")
        attrs = {k: v for k, v in self.attrs.items() if k != "commit"}
        revisions = (
            ({}, False),
            ({"tag": "v0.7.0"}, False),
            ({"tag": SHA}, False),
            ({"commit": "main"}, False),
            ({"commit": SHA[:12]}, False),
            ({"commit": "z" * 40}, False),
            ({"commit": SHA}, True),
            ({"commit": "b" * 64}, True),
            ({"commit": SHA, "tag": "v0.7.0"}, True),
        )
        for (revision, pinned), cached in itertools.product(revisions, (False, True)):
            with self.subTest(revision=revision, cached=cached):
                # A stale archive checksum cannot prove Git checkout contents.
                data = lockfile({**attrs, **revision, "sha256": "c" * 64})
                specs = data["moduleExtensions"][EXTENSION]["general"][
                    "generatedRepoSpecs"
                ]
                specs[other_repo.rsplit("+", 1)[-1]] = copy.deepcopy(
                    next(iter(specs.values()))
                )
                path = self.write("git-hubs.json", data)
                metadata = {"crate_sources": parse_module_bazel_lock(path)}
                if cached:
                    with (
                        patch(
                            "scripts.generate_crates_metadata_cache.fetch_crate_metadata_from_cratesio",
                            return_value={},
                        ),
                        patch("sys.stderr", new_callable=io.StringIO),
                    ):
                        metadata = {
                            "crates": json.loads(
                                json.dumps(generate_cache(module_lock_paths=[path]))
                            )
                        }
                components = [
                    resolve_component(repo, metadata) for repo in (REPO, other_repo)
                ]
                for ordered in (components, list(reversed(components))):
                    if pinned:
                        self.assertEqual(len(deduplicate_components(ordered)), 1)
                    else:
                        with self.assertRaisesRegex(
                            ValueError, "Conflicting crate repositories"
                        ):
                            deduplicate_components(ordered)

    def test_tag_only_sources_remain_reportable_and_same_repo_can_merge(self):
        attrs = {"remote": REMOTE, "tag": "v0.7.0"}
        path = self.write("tag.json", lockfile(attrs))
        component = resolve_component(
            REPO, {"crate_sources": parse_module_bazel_locks([path, path])}
        )
        duplicate = {**component, "description": "Same repository"}
        merged = deduplicate_components([component, duplicate])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["description"], "Same repository")
        spdx = generate_spdx(merged, {}, "2026-01-01T00:00:00Z")["packages"][1]
        cdx = generate_cyclonedx(merged, {}, "2026-01-01T00:00:00Z")["components"][0]
        self.assertEqual(
            spdx["externalRefs"][0]["referenceLocator"],
            "pkg:github/qorix-group/iceoryx2@v0.7.0",
        )
        self.assertEqual(cdx["purl"], spdx["externalRefs"][0]["referenceLocator"])
        self.assertEqual(spdx["downloadLocation"], "git+" + REMOTE + "@v0.7.0")
        self.assertEqual(
            cdx["externalReferences"],
            [{"type": "vcs", "url": spdx["downloadLocation"]}],
        )
        self.assertIn('tag: "v0.7.0"', spdx["sourceInfo"])
        self.assertIn(spdx["sourceInfo"], cdx["pedigree"]["notes"])
        self.assertNotIn("checksums", spdx)
        self.assertNotIn("hashes", cdx)
        self.assertNotIn("git_commit", json.dumps([spdx, cdx]))

    def test_github_clone_aliases_merge_across_lockfiles_variants_and_hubs(self):
        other_repo = REPO.replace("crate_index__", "crates__")
        aliases = [
            (REMOTE, REMOTE.removesuffix(".git")),
            (REMOTE, REMOTE + "/"),
            (REMOTE, "https://github.com/Qorix-Group/Iceoryx2.git"),
            (REMOTE, "https://github.com/QORIX-GROUP/ICEORYX2.GIT"),
            (REMOTE, "HTTPS://GITHUB.COM:443/Qorix-Group/Iceoryx2.git"),
            (
                "git@github.com:qorix-group/iceoryx2.git",
                "ssh://git@github.com/qorix-group/iceoryx2",
            ),
            (
                REMOTE.replace("https://", "https://reader:secret@"),
                REMOTE.removesuffix(".git").replace(
                    "https://", "https://reader:secret@"
                ),
            ),
        ]
        for (scheme, port), userinfo in itertools.product(
            (
                ("https", 443),
                ("http", 80),
                ("ssh", 22),
                ("git", 9418),
                ("git+https", 443),
                ("git+ssh", 22),
            ),
            ("", "Reader:CaseSensitive%40Token@"),
        ):
            left = f"{scheme}://{userinfo}github.com/qorix-group/iceoryx2.git"
            aliases.extend(
                (left, f"{scheme}://{userinfo}{authority}/QORIX-GROUP/ICEORYX2.GIT")
                for authority in (
                    "GITHUB.COM",
                    f"github.com:{port}",
                    f"GitHub.Com:0{port}",
                )
            )
        for left, right in aliases:
            with self.subTest(left=left, right=right):
                attrs = {
                    **self.attrs,
                    "remote_patches": {"https://example.org/fix": "sha256-first"},
                }
                entries = [
                    lockfile({**attrs, "remote": remote}) for remote in (left, right)
                ]
                paths = [
                    self.write(f"alias-{i}.json", entry)
                    for i, entry in enumerate(entries)
                ]
                self.assertEqual(len(parse_module_bazel_locks(paths)), 1)
                variants = copy.deepcopy(entries[0])
                variants["moduleExtensions"][EXTENSION]["other"] = entries[1][
                    "moduleExtensions"
                ][EXTENSION]["general"]
                self.assertEqual(
                    len(parse_module_bazel_lock(self.write("aliases.json", variants))),
                    1,
                )
                components = [
                    resolve_component(
                        repo,
                        {"crate_sources": {repo: parse_module_bazel_lock(path)[REPO]}},
                    )
                    for repo, path in zip((REPO, other_repo), paths)
                ]
                self.assertEqual(components[0]["purl"], components[1]["purl"])
                # Display annotations must neither establish nor veto source equality.
                components[0]["purl"] = "pkg:generic/annotated-first@1.0"
                components[1]["purl"] = "pkg:generic/annotated-second@1.0"
                self.assertEqual(len(deduplicate_components(components)), 1)
                with (
                    patch(
                        "scripts.generate_crates_metadata_cache.fetch_crate_metadata_from_cratesio",
                        return_value={},
                    ),
                    patch("sys.stderr", new_callable=io.StringIO),
                ):
                    cache = json.loads(
                        json.dumps(generate_cache(module_lock_paths=paths))
                    )
                cached = resolve_component(REPO, {"crates": cache})
                self.assertEqual(
                    cached["source_fingerprint"], components[0]["source_fingerprint"]
                )

    def test_normalized_git_comparison_keeps_all_private_checkout_differences(self):
        other_repo = REPO.replace("crate_index__", "crates__")
        attrs = {
            **self.attrs,
            "remote": "https://reader:first-secret@github.com/qorix-group/iceoryx2.git",
            "remote_patches": {
                "https://reader:first-secret@patches.example/fix": "sha256-first",
                "https://patches.example/second": "sha256-second",
            },
        }
        changes = (
            {"remote": attrs["remote"].replace("first-secret", "different-secret")},
            {"remote": attrs["remote"].replace("reader:", "Reader:")},
            {"remote": attrs["remote"].replace("first-secret", "First-secret")},
            {"remote": attrs["remote"] + "?token=different-secret"},
            {"remote": attrs["remote"].replace("github.com/", "github.com:8443/")},
            {"remote": attrs["remote"].replace("iceoryx2.git", "other.git")},
            {"commit": "b" * 40},
            {"tag": "different-tag"},
            {"strip_prefix": "other/subdir"},
            {"init_submodules": True},
            {"recursive_init_submodules": True},
            {"patches": ["//patches:other.patch"]},
            {"patch_args": ["-p2"]},
            {"patch_cmds": ["echo changed"]},
            {"patch_cmds_win": ["echo changed"]},
            {"patch_tool": "custom-patch"},
            {"remote_patches": dict(reversed(list(attrs["remote_patches"].items())))},
            {
                "remote_patches": {
                    url.replace("first-secret", "other-secret"): digest
                    for url, digest in attrs["remote_patches"].items()
                }
            },
            {"remote_patch_strip": 1},
        )
        original_path = self.write("original.json", lockfile(attrs))
        original = resolve_component(
            REPO, {"crate_sources": parse_module_bazel_lock(original_path)}
        )
        for change in changes:
            with self.subTest(change=change):
                path = self.write("different.json", lockfile({**attrs, **change}))
                with self.assertRaisesRegex(ValueError, "Conflicting crate sources"):
                    parse_module_bazel_locks([original_path, path])
                different = resolve_component(
                    other_repo,
                    {
                        "crate_sources": {
                            other_repo: parse_module_bazel_lock(path)[REPO]
                        }
                    },
                )
                different["purl"] = original["purl"]
                different["source_info"] = original["source_info"]
                different["download_location"] = original["download_location"]
                with self.assertRaisesRegex(
                    ValueError, "Conflicting crate repositories"
                ):
                    deduplicate_components([original, different])

        for remote in (
            "https://git.example/owner/repo",
            "git@host:repo",
            "/local/repo",
            "https://github.com:8443/owner/repo",
        ):
            with self.subTest(remote=remote):
                paths = [
                    self.write(
                        f"distinct-{i}.json", lockfile({"remote": value, "commit": SHA})
                    )
                    for i, value in enumerate((remote, remote + ".git"))
                ]
                with self.assertRaisesRegex(ValueError, "Conflicting crate sources"):
                    parse_module_bazel_locks(paths)

        for remote in (
            "https://git.example/Owner/Repo.git",
            "https://github.com:8443/Owner/Repo.git",
            "/local/Repo.git",
        ):
            paths = [
                self.write(f"case-{i}.json", lockfile({"remote": value, "commit": SHA}))
                for i, value in enumerate((remote, remote.lower()))
            ]
            with (
                self.subTest(remote=remote),
                self.assertRaisesRegex(ValueError, "Conflicting crate sources"),
            ):
                parse_module_bazel_locks(paths)

    def test_standalone_cache_retains_sources_for_each_crate_repository(self):
        other_repo = REPO.replace("crate_index__", "crates__")
        tag_only = {k: v for k, v in self.attrs.items() if k != "commit"}
        for other_attrs in (
            {**self.attrs, "remote": "https://github.com/other/iceoryx2.git"},
            {**self.attrs, "commit": "b" * 40},
            {**tag_only, "tag": "v0.7.0"},
            {**self.attrs, "strip_prefix": "other/subdirectory"},
            {**self.attrs, "patches": ["//patches:other.patch"]},
            {"urls": ["https://example.org/crate.tar.gz"], "sha256": "c" * 64},
        ):
            with self.subTest(other_attrs=other_attrs):
                entries = [(REPO, self.attrs), (other_repo, other_attrs)]
                caches = []
                for ordered in (entries, list(reversed(entries))):
                    data = {
                        "moduleExtensions": {
                            EXTENSION: {
                                "general": {
                                    "generatedRepoSpecs": {
                                        repo.rsplit("+", 1)[-1]: {"attributes": attrs}
                                        for repo, attrs in ordered
                                    }
                                }
                            }
                        }
                    }
                    path = self.write("standalone.json", data)
                    with (
                        patch(
                            "scripts.generate_crates_metadata_cache.fetch_crate_metadata_from_cratesio",
                            return_value={},
                        ),
                        patch("sys.stderr", new_callable=io.StringIO),
                    ):
                        cache = json.loads(
                            json.dumps(generate_cache(module_lock_paths=[path]))
                        )
                    self.assertEqual(set(cache), {"repo:" + REPO, "repo:" + other_repo})
                    caches.append(cache)
                    sources = parse_module_bazel_lock(path)
                    components = []
                    for repo, _ in entries:
                        component = resolve_component(repo, {"crates": cache})
                        expected = resolve_component(repo, {"crate_sources": sources})
                        for field in (
                            "purl",
                            "version",
                            "source",
                            "url",
                            "download_location",
                            "source_info",
                            "checksum",
                            "source_fingerprint",
                            "archive_source",
                        ):
                            self.assertEqual(
                                component.get(field, ""), expected.get(field, ""), field
                            )
                        components.append(component)
                    with self.assertRaisesRegex(
                        ValueError, "Conflicting crate repositories"
                    ):
                        deduplicate_components(components)
                self.assertEqual(caches[0], caches[1])

    def test_repository_cache_does_not_inherit_legacy_source_attributes(self):
        legacy = {
            "name": CRATE,
            "version": "0.7.0",
            **self.attrs,
            "cpe": "cpe:/a:example:lib:0.7.0",
        }
        for current in (
            {"remote": "https://github.com/other/lib.git", "tag": "v0.7.0"},
            {"remote": REMOTE, "commit": "b" * 40},
            {
                "source": REGISTRY_SOURCES[0],
                "source_url": "https://example.org/lib.tar.gz",
                "checksum": "c" * 64,
            },
        ):
            with self.subTest(current=current):
                entry = {"name": CRATE, "version": "0.7.0", **current}
                cache = {CRATE + "@0.7.0": legacy, "repo:" + REPO: entry}
                component = resolve_component(REPO, {"crates": cache})
                expected = resolve_component(REPO, {"crates": {"repo:" + REPO: entry}})
                for field in (
                    "purl",
                    "source",
                    "download_location",
                    "source_info",
                    "checksum",
                    "source_fingerprint",
                    "archive_source",
                ):
                    self.assertEqual(component.get(field), expected.get(field), field)
                self.assertEqual(component["cpe"], legacy["cpe"])

    def test_legacy_repository_metadata_is_not_reused_by_another_hub(self):
        legacy = {
            "name": CRATE,
            "version": "0.7.0",
            **self.attrs,
            "bazel_repository": REPO,
            "license": "MIT",
            "cpe": "cpe:/a:old:fork:0.7.0",
        }
        other_repo = REPO.replace("crate_index__", "crates__")
        cache = {CRATE + "@0.7.0": legacy}
        own = resolve_component(REPO, {"crates": cache})
        self.assertIn(SHA, own["purl"])
        missing = resolve_component(other_repo, {"crates": cache})
        self.assertNotEqual(missing["source"], "git")
        self.assertFalse(missing.get("source_info"))
        self.assertFalse(missing.get("license"))
        cache["repo:" + other_repo] = {
            "name": CRATE,
            "version": "0.7.0",
            "remote": "https://github.com/other/lib.git",
            "tag": "v0.7.0",
        }
        current = resolve_component(other_repo, {"crates": cache})
        self.assertEqual(current["purl"], "pkg:github/other/lib@v0.7.0")
        self.assertFalse(current.get("license"))
        self.assertFalse(current.get("cpe"))

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

    def test_archive_deduplication_checks_extraction_and_modifications(self):
        second_repo = REPO.replace("crate_index__", "crates__")

        def components(first, second, cached):
            data = lockfile(first)
            specs = data["moduleExtensions"][EXTENSION]["general"]["generatedRepoSpecs"]
            specs["crates__" + CRATE + "-0.7.0"] = {"attributes": second}
            sources = parse_module_bazel_lock(self.write("archives.json", data))
            metadata = (
                {"crates": {"repo:" + repo: info for repo, info in sources.items()}}
                if cached
                else {"crate_sources": sources}
            )
            return [resolve_component(repo, metadata) for repo in (REPO, second_repo)]

        for patches in (
            {},
            {"patches": ["//:fix.patch"]},
            {"patch_cmds": ["touch changed"]},
            {"remote_patches": {"https://example.com/fix.patch": "sha256-hash"}},
        ):
            attrs = {
                "urls": ["https://example.com/crate.tar.gz"],
                "sha256": "a" * 64,
                "strip_prefix": "selected/crate",
                **patches,
            }
            for cached in (False, True):
                with self.subTest(patches=patches, cached=cached):
                    mirror = {
                        **attrs,
                        "urls": ["https://mirror.example.com/crate.tar.gz"],
                    }
                    for first, second in ((attrs, mirror), (mirror, attrs)):
                        merged = deduplicate_components(
                            components(first, second, cached)
                        )
                        self.assertEqual(len(merged), 1)
                        spdx = generate_spdx(merged, {}, "2026-01-01T00:00:00Z")[
                            "packages"
                        ][1]
                        cdx = generate_cyclonedx(merged, {}, "2026-01-01T00:00:00Z")[
                            "components"
                        ][0]
                        self.assertEqual("checksums" in spdx, not bool(patches))
                        self.assertEqual("hashes" in cdx, not bool(patches))
                        self.assertNotIn("archive_source", spdx)
                        self.assertNotIn("archive_source", cdx)
                    changes = [
                        {"sha256": "b" * 64},
                        {"strip_prefix": "different/crate"},
                        {"strip_prefix": ""},
                        {"patches": ["//:other.patch"]},
                        {"patch_cmds": ["touch different"]},
                        {"patch_cmds_win": ["echo different"]},
                        {
                            "remote_patches": {
                                "https://example.com/other.patch": "sha256-other"
                            }
                        },
                    ]
                    if patches:
                        changes += [
                            {field: value}
                            for field, value in (
                                ("patch_args", ["-p1"]),
                                ("patch_tool", "custom-patch"),
                                ("patch_strip", 1),
                                ("remote_patch_strip", 1),
                            )
                        ]
                    for change in changes:
                        with (
                            self.subTest(change=change),
                            self.assertRaisesRegex(
                                ValueError, "Conflicting crate repositories"
                            ),
                        ):
                            deduplicate_components(
                                components(attrs, {**attrs, **change}, cached)
                            )
                    missing_hash = {**attrs, "sha256": ""}
                    with self.assertRaisesRegex(
                        ValueError, "Conflicting crate repositories"
                    ):
                        deduplicate_components(
                            components(missing_hash, missing_hash, cached)
                        )

    def test_generator_merges_patched_hubs_and_preserves_annotations_and_edges(self):
        attrs = {
            "urls": ["https://example.com/crate.tar.gz"],
            "sha256": "a" * 64,
            "strip_prefix": CRATE + "-0.7.0",
            "patches": ["//:fix.patch"],
        }
        data = lockfile(attrs)
        second_repo = REPO.replace("crate_index__", "crates__")
        data["moduleExtensions"][EXTENSION]["general"]["generatedRepoSpecs"][
            "crates__" + CRATE + "-0.7.0"
        ] = {
            "attributes": {**attrs, "urls": ["https://mirror.example.com/crate.tar.gz"]}
        }
        inputs = self.write(
            "input.json",
            {
                "external_repos": ["score_time+", "other+", REPO],
                "external_dep_edges": [
                    "score_time+::" + REPO,
                    "other+::" + second_repo,
                ],
                "module_lockfiles": [self.write("lock.json", data)],
            },
        )
        metadata = self.write(
            "metadata.json",
            {
                "git_overrides": {"score_time": self.attrs},
                "modules": {"other": {"version": "1.0"}},
                "licenses": {
                    "score_time": {"license": "MIT", "supplier": "Annotated supplier"}
                },
            },
        )
        spdx_path, cdx_path = self.root / "spdx.json", self.root / "cdx.json"
        with patch(
            "sys.argv",
            [
                "sbom",
                "--input",
                inputs,
                "--metadata",
                metadata,
                "--spdx-output",
                str(spdx_path),
                "--cyclonedx-output",
                str(cdx_path),
            ],
        ):
            self.assertEqual(main(), 0)
        spdx = json.loads(spdx_path.read_text())
        cdx = json.loads(cdx_path.read_text())
        for entries in (spdx["packages"], cdx["components"]):
            self.assertEqual(sum(entry["name"] == CRATE for entry in entries), 1)
        package = next(entry for entry in spdx["packages"] if entry["name"] == CRATE)
        component = next(entry for entry in cdx["components"] if entry["name"] == CRATE)
        self.assertNotIn("checksums", package)
        self.assertNotIn("hashes", component)
        self.assertIn("//:fix.patch", package["sourceInfo"])
        for name in ("score_time", "other"):
            parent = next(entry for entry in spdx["packages"] if entry["name"] == name)
            self.assertIn(
                {
                    "spdxElementId": parent["SPDXID"],
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": package["SPDXID"],
                },
                spdx["relationships"],
            )
            parent_cdx = next(
                entry for entry in cdx["components"] if entry["name"] == name
            )
            dependency = next(
                entry
                for entry in cdx["dependencies"]
                if entry["ref"] == parent_cdx["bom-ref"]
            )
            self.assertIn(component["bom-ref"], dependency["dependsOn"])
            if name == "score_time":
                self.assertEqual(parent["licenseDeclared"], "MIT")
                self.assertEqual(parent["supplier"], "Organization: Annotated supplier")
                self.assertEqual(parent_cdx["licenses"], [{"license": {"id": "MIT"}}])

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
            self.assertIn("patch_cmds", note)
            self.assertIn("sha256:", note)
            self.assertNotIn("touch modified", note)
            self.assertIn("SHA256 of unmodified source archive: " + "f" * 64, note)


if __name__ == "__main__":
    unittest.main()
