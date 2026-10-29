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

"""Cross-boundary credential and source-identity audit regressions."""

import copy
import io
import json
import tempfile
import unittest
import traceback
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote, quote_plus, unquote, urlsplit

from internal.generator.source_identity import crate_source_identity, git_identity
from internal.generator.sbom_generator import (
    apply_known_licenses,
    deduplicate_components,
    enrich_components_from_cpp_cache,
    resolve_component,
)
from internal.generator.spdx_formatter import generate_spdx
from internal.generator.cyclonedx_formatter import generate_cyclonedx
from internal.generator.reporting import redact_credentials
from internal.generator.registry_metadata import registry_source_hashes
from internal.generator.sbom_generator import parse_module_lockfiles
from scripts.generate_crates_metadata_cache import generate_cache
from scripts.generate_registry_metadata_cache import generate_cache as registry_cache

SHA = "a" * 40
REPO = "rules_rust++crate+crate_index__lib-1.0.0"
OTHER = REPO.replace("crate_index__", "crates__")
PRIVATE = "https://audit-user:audit-password@packages.example/lib.tar.gz"
PATCHES = {
    "https://first:audit-first@patches.example/fix.patch": "sha256-first",
    "https://second:audit-second@patches.example/fix.patch": "sha256-second",
    "https://third:audit-unicode-秘密@patches.example/fix.patch": "sha256-third",
}
STAMP = "2026-11-02T00:00:00Z"


class TestReportingAudit(unittest.TestCase):
    def reports(self, component, config=None):
        return [
            generate_spdx([component], config or {}, STAMP),
            generate_cyclonedx([component], config or {}, STAMP),
        ]

    def test_archive_and_patch_urls_are_private_without_changing_evidence(self):
        for source in (
            {"source_url": PRIVATE, "checksum": "b" * 64},
            {"remote": PRIVATE, "commit": SHA},
        ):
            with self.subTest(source=source):
                info = {
                    "name": "lib",
                    "version": "1.0.0",
                    **source,
                    "remote_patches": PATCHES,
                }
                before = copy.deepcopy(info)
                component = resolve_component(REPO, {"crate_sources": {REPO: info}})
                for report in self.reports(component):
                    rendered = json.dumps(report)
                    for secret in (
                        "audit-password",
                        "audit-first",
                        "audit-second",
                        "audit-unicode-",
                    ):
                        self.assertNotIn(secret, rendered)
                    self.assertIn("sha256-first", rendered)
                    self.assertLess(
                        rendered.index("sha256-first"), rendered.index("sha256-second")
                    )
                self.assertEqual(info, before)
                identical = resolve_component(OTHER, {"crate_sources": {OTHER: info}})
                self.assertEqual(len(deduplicate_components([component, identical])), 1)
                for patches in (
                    dict(reversed(list(PATCHES.items()))),
                    {
                        key.replace("audit-first", "different-secret"): value
                        for key, value in PATCHES.items()
                    },
                ):
                    changed = resolve_component(
                        OTHER,
                        {"crate_sources": {OTHER: {**info, "remote_patches": patches}}},
                    )
                    with self.assertRaisesRegex(
                        ValueError, "Conflicting crate repositories"
                    ):
                        deduplicate_components([component, changed])

    def test_output_boundary_covers_cached_and_annotated_data(self):
        nested = quote(
            "https://audit-user:audit-password@git.example/repo.git", safe=""
        )
        component = {
            "name": "lib",
            "version": "1.0",
            "type": "library",
            "url": PRIVATE,
            "purl": "pkg:generic/lib@1.0?vcs_url=" + nested,
            "source_info": "Previous cache: "
            + PRIVATE
            + "; patches: "
            + json.dumps(PATCHES),
            "pedigree_notes": "Authorization: Bearer audit-bearer; See " + PRIVATE,
            "aliases": [PRIVATE],
            "description": "Mirror: " + PRIVATE,
        }
        config = {"producer_url": PRIVATE, "namespace": PRIVATE}
        before = copy.deepcopy((component, config))
        for report in self.reports(component, config):
            rendered = json.dumps(report)
            self.assertNotIn("audit-password", rendered)
            self.assertNotIn("audit-bearer", rendered)
            self.assertNotIn("audit-unicode-", rendered)
            self.assertNotIn(quote("audit-user:audit-password", safe=""), rendered)
        self.assertEqual((component, config), before)
        safe = {
            **component,
            "purl": "pkg:generic/lib@1.0?repository_url=https%3A%2F%2Fexample.org%2Frepo",
        }
        self.assertEqual(
            generate_cyclonedx([safe], {}, STAMP)["components"][0]["purl"], safe["purl"]
        )
        config = {
            "component_name": "root",
            "component_version": "1.0",
            "producer_url": "https://github.com/acme?token=audit-secret",
        }
        report = generate_cyclonedx([safe], config, STAMP)
        self.assertNotIn("audit-secret", json.dumps(report))
        self.assertEqual(
            report["metadata"]["component"]["purl"], "pkg:github/acme/root@1.0"
        )
        config["producer_url"] = (
            "https://audit-user:audit-password@github.com/acme?token=audit-secret"
        )
        report = generate_cyclonedx([safe], config, STAMP)
        self.assertNotIn("audit-password", json.dumps(report))
        self.assertEqual(
            report["metadata"]["component"]["purl"], "pkg:github/acme/root@1.0"
        )
        credential_purl = {**safe, "purl": "pkg:generic/lib@1.0?token=audit-secret"}
        for report in self.reports(credential_purl):
            self.assertNotIn("audit-secret", json.dumps(report))

    def test_query_secrets_and_ssh_passwords_are_not_published(self):
        for query in (
            "access_token=audit-secret&download=1",
            "X-Amz-Credential=audit-secret&X-Amz-Signature=audit-signature",
            "sig=audit-secret&file=lib",
            "api%5Fkey=audit-secret",
        ):
            with self.subTest(query=query):
                component = {
                    "name": "lib",
                    **git_identity(
                        "1.0",
                        {
                            "remote": "https://git.example/lib.git?" + query,
                            "commit": SHA,
                        },
                    ),
                }
                for report in self.reports(component):
                    self.assertNotIn("audit-secret", json.dumps(report))
                    self.assertNotIn("audit-signature", json.dumps(report))
                self.assertTrue(
                    urlsplit(component["download_location"]).path.endswith("@" + SHA)
                )
        ssh = {
            "name": "lib",
            **git_identity(
                "1.0",
                {"remote": "ssh://alice:audit-password@host/~/lib.git", "commit": SHA},
            ),
        }
        for report in self.reports(ssh):
            self.assertNotIn("audit-password", json.dumps(report))
        self.assertIn("/~alice/", ssh["purl"])
        encoded = "pkg:generic/lib@1.0?vcs_url=" + quote(
            "git+ssh://alice:audit-password@host/~/lib.git", safe=""
        )
        public = redact_credentials(encoded)
        self.assertNotIn("audit-password", public)
        self.assertIn("alice%40host", public)

    def test_userinfo_punctuation_is_redacted_before_text_or_query_splitting(self):
        # RFC 3986 userinfo includes all sub-delimiters, including apostrophes.
        for scheme in ("https", "git+https", "ssh", "git+ssh", "ftp"):
            for char in "!$&'()*+,;=:":
                with self.subTest(scheme=scheme, char=char):
                    remote = (
                        f"{scheme}://reader:audit{char}secret@mirror.example/lib.git"
                    )
                    public = (
                        f"{scheme}://"
                        + ("reader@" if "ssh" in scheme else "")
                        + "mirror.example/lib.git"
                    )
                    self.assertEqual(
                        redact_credentials("Mirror: '" + remote + "'"),
                        "Mirror: '" + public + "'",
                    )
                    info = {"remote": remote, "commit": SHA}
                    original = copy.deepcopy(info)
                    component = {"name": "lib", **git_identity("1.0", info)}
                    for encode in (
                        str,
                        quote,
                        quote_plus,
                        lambda s: quote(s, safe=":/"),
                    ):
                        value = (
                            "pkg:generic/lib@1.0?vcs_url="
                            + encode(remote)
                            + "&download=1"
                        )
                        redacted = redact_credentials(value)
                        self.assertNotIn("audit", redacted)
                        self.assertNotIn("secret", redacted)
                        self.assertTrue(redacted.endswith("&download=1"))
                        self.assertEqual(redact_credentials(redacted), redacted)
                        for report in self.reports(
                            {
                                **component,
                                "description": value,
                                "pedigree_notes": json.dumps([remote]),
                            }
                        ):
                            self.assertNotIn("secret", json.dumps(report))
                    self.assertEqual(info, original)
        ssh = "ssh://o'brien:pa'ss@host/~/lib.git?token=audit-token"
        self.assertEqual(
            redact_credentials(ssh), "ssh://o'brien@host/~/lib.git?token=REDACTED"
        )
        unicode_password = "https://reader:pa'ss秘密@mirror.example/lib.git"
        self.assertEqual(
            redact_credentials(json.dumps([unicode_password])),
            json.dumps(["https://mirror.example/lib.git"]),
        )
        for prefix in ("https%3A//", "https%3A%2F%2F", "https:/%2F"):
            value = prefix + "reader:audit'password%40mirror.example/lib"
            self.assertNotIn("audit", redact_credentials(value))
        for safe in (
            "See 'https://mirror.example/lib.git' and 'https://other.example/file'",
            "https://mirror.example/team/o'brien.git",
        ):
            self.assertEqual(redact_credentials(safe), safe)

    def test_apostrophes_in_paths_and_parameters_do_not_end_urls(self):
        for path in ("/lib.tar.gz", "/team/o'brien.tar.gz"):
            for marker in ("?", "#"):
                for secret in (
                    "audit-secret",
                    "audit'before'after",
                    "'audit-secret'",
                    "audit-secret'",
                ):
                    private = (
                        "https://mirror.example"
                        + path
                        + marker
                        + "access_token="
                        + secret
                    )
                    public = (
                        "https://mirror.example"
                        + path
                        + marker
                        + "access_token=REDACTED"
                    )
                    for wrap in (
                        str,
                        lambda s: "Mirror: '" + s + "'.",
                        lambda s: json.dumps({"source": s}),
                    ):
                        with self.subTest(
                            path=path, marker=marker, secret=secret, wrapper=wrap
                        ):
                            value = wrap(private)
                            redacted = redact_credentials(value)
                            self.assertEqual(redacted, wrap(public))
                            self.assertEqual(redact_credentials(redacted), redacted)
                            component = {
                                "name": "lib",
                                "version": "1.0",
                                "url": private,
                                "source_info": value,
                                "description": value,
                            }
                            before = copy.deepcopy(component)
                            for report in self.reports(component):
                                rendered = json.dumps(report)
                                self.assertNotIn("audit", rendered)
                                self.assertNotIn("after", rendered)
                            self.assertEqual(component, before)
                    for encode in (quote, quote_plus, lambda s: quote(s, safe=":/")):
                        encoded = (
                            "pkg:generic/lib@1.0?vcs_url="
                            + encode(private)
                            + "&download=1"
                        )
                        redacted = redact_credentials(encoded)
                        self.assertNotIn("audit", redacted)
                        self.assertNotIn("after", redacted)
                        self.assertTrue(redacted.endswith("&download=1"))
                        self.assertEqual(redact_credentials(redacted), redacted)
        safe = "https://mirror.example/team/o'brien.tar.gz?file='report'"
        self.assertEqual(redact_credentials(safe), safe)
        quoted = "'https://mirror.example/lib?token=audit'credential', '" + safe + "'"
        self.assertEqual(
            redact_credentials(quoted),
            "'https://mirror.example/lib?token=REDACTED', '" + safe + "'",
        )

    def test_nested_url_credentials_are_redacted_in_both_formats(self):
        encoders = (quote, quote_plus, lambda s: quote(s, safe=":/"))
        for remote in (
            "https://reader:audit-password@mirror.example/lib?token=audit-token",
            "git+https://reader:audit-password@mirror.example/lib.git",
            "ssh://alice:audit-password@host/~/lib.git",
            "git://reader:audit-password@mirror.example/lib.git",
            "git+git://reader:audit-password@mirror.example/lib.git",
            "ftp://reader:audit-password@mirror.example/lib.tar.gz",
            "ftps://reader:audit-password@mirror.example/lib.tar.gz",
            "git+ftp://reader:audit-password@mirror.example/lib.git",
            "custom+transport://reader:audit-password@mirror.example/lib.git",
        ):
            for encode in encoders:
                for layers in (0, 1, 3):
                    nested = remote
                    for _ in range(layers):
                        nested = encode(nested)
                    for prefix in (
                        "https://proxy.example/download?url=",
                        "https://proxy.example/download#url=",
                        "pkg:generic/lib@1.0?vcs_url=",
                        "https://proxy.example/download/",
                        "https://proxy.example/download#",
                    ):
                        with self.subTest(remote=remote, nested=nested, prefix=prefix):
                            value = prefix + nested + "&download=1"
                            public = redact_credentials(value)
                            self.assertNotIn("audit-password", public)
                            self.assertNotIn("audit-token", public)
                            self.assertEqual(redact_credentials(public), public)
                            decoded = public
                            for _ in range(layers):
                                decoded = unquote(decoded)
                            self.assertIn("download=1", decoded)
                            if remote.startswith("ssh:"):
                                self.assertIn("alice@host/~/lib.git", decoded)
                            component = {
                                "name": "lib",
                                "version": "1.0",
                                "url": value,
                                "source_info": "Mirror: " + value,
                                "purl": value if prefix.startswith("pkg:") else "",
                            }
                            before = copy.deepcopy(component)
                            for report in self.reports(component):
                                rendered = json.dumps(report)
                                self.assertNotIn("audit-password", rendered)
                                self.assertNotIn("audit-token", rendered)
                            self.assertEqual(component, before)

    def test_transport_credentials_are_removed_even_from_provenance_only_remotes(self):
        for scheme in (
            "git",
            "git+git",
            "ftp",
            "ftps",
            "git+ftp",
            "sftp",
            "rsync",
            "svn+ssh",
            "custom+transport",
        ):
            for host in ("host", "[2001:db8::1]:9418", "host:bad", "[invalid"):
                with self.subTest(scheme=scheme, host=host):
                    public = f"{scheme}://{host}/lib.git"
                    private = f"{scheme}://reader:audit-password@{host}/lib.git"
                    self.assertEqual(redact_credentials(private), public)
                    self.assertEqual(redact_credentials(public), public)
                    info = {"remote": private, "commit": SHA}
                    before = copy.deepcopy(info)
                    component = {"name": "lib", **git_identity("1.0", info)}
                    if scheme not in ("git", "git+git"):
                        self.assertFalse(component["purl"])
                        self.assertFalse(component["download_location"])
                    self.assertIn(public, component["source_info"])
                    for report in self.reports(component):
                        self.assertNotIn("audit-password", json.dumps(report))
                    self.assertEqual(info, before)

    def test_encoded_url_notes_and_safe_nested_values(self):
        for encode in (quote, quote_plus):
            for layers in (1, 2, 4):
                for remote in (
                    "https://mirror.example/lib?ref=release%2F1&file=a%2Bb",
                    "git+ssh://alice@host/~/lib.git?ref=release+1",
                ):
                    safe = remote
                    private = "https://reader:audit-password@mirror.example/lib"
                    for _ in range(layers):
                        safe, private = encode(safe), encode(private)
                    with self.subTest(safe=safe, layers=layers):
                        for value in (
                            "Mirror: " + safe,
                            "pkg:generic/lib@1.0?url=" + safe,
                        ):
                            self.assertEqual(redact_credentials(value), value)
                        public = redact_credentials("Mirror: " + private)
                        self.assertNotIn("audit-password", public)
                        self.assertEqual(redact_credentials(public), public)

        public = "https://mirror.example/lib%2Fpart?ref=release%2B1&file=a%20b"
        private = public.replace("https://", "https://reader:audit-password@")
        wrapped = "pkg:generic/lib@1.0?vcs_url=" + quote(private, safe="")
        self.assertEqual(
            redact_credentials(wrapped),
            "pkg:generic/lib@1.0?vcs_url=" + quote(public, safe=""),
        )

    def test_mixed_url_encoding_redacts_literal_query_and_fragment_credentials(self):
        for scheme in ("https", "git+ssh", "ftp"):
            for encode in (quote, quote_plus):
                for tail in (
                    "?access_token=audit-secret&download=1",
                    "?download=1&access_token=audit-secret",
                    "#access_token=audit-secret&download=1",
                    "?download=1#access_token=audit-secret",
                    r"?download=1&access_token=\u79d8\u5bc6",
                ):
                    with self.subTest(scheme=scheme, encode=encode, tail=tail):
                        value = encode(f"{scheme}://mirror.example/lib") + tail
                        public = redact_credentials("Mirror: " + value)
                        self.assertNotIn("audit-secret", public)
                        self.assertNotIn("%5Cu79d8", public)
                        self.assertNotIn(r"\u79d8", public)
                        self.assertIn("download=1", unquote(public))
                        self.assertEqual(redact_credentials(public), public)
                        component = {
                            "name": "lib",
                            "version": "1.0",
                            "description": "Mirror: " + value,
                            "source_info": "Mirror: " + value,
                        }
                        for report in self.reports(component):
                            rendered = json.dumps(report)
                            self.assertNotIn("audit-secret", rendered)
                            self.assertNotIn("%5Cu79d8", rendered)
                            self.assertNotIn(r"\u79d8", rendered)

        inner = "https%3A//reader%3Aaudit-secret%40mirror.example/lib?access_token=audit-secret"
        original = "pkg:generic/lib@1.0?vcs_url=" + inner + "&download=1#src/lib"
        public = redact_credentials(original)
        self.assertEqual(
            public,
            "pkg:generic/lib@1.0?vcs_url="
            + quote("https://mirror.example/lib?access_token=REDACTED", safe="")
            + "&download=1#src/lib",
        )
        safe = "Mirror: https%3A//mirror.example/lib?download=1#src/lib"
        self.assertEqual(redact_credentials(safe), safe)

    def test_encoded_password_delimiters_are_removed_before_decoding(self):
        for scheme in ("https", "git+https", "ssh", "git+ssh", "ftp"):
            for separator in ("%3F", "%23", "%2F"):
                for authority_end in ("@", "%40", "%2540"):
                    private = f"{scheme}://reader:audit{separator}secret{authority_end}mirror.example/lib"
                    for encode in (
                        str,
                        quote,
                        quote_plus,
                        lambda s: quote(s, safe=":/"),
                    ):
                        value = encode(private)
                        for prefix in ("Mirror: ", "pkg:generic/lib@1.0?vcs_url="):
                            with self.subTest(
                                scheme=scheme,
                                separator=separator,
                                end=authority_end,
                                prefix=prefix,
                                value=value,
                            ):
                                public = redact_credentials(prefix + value)
                                self.assertNotIn("audit", public)
                                self.assertNotIn("secret", public)
                                self.assertIn("mirror.example", public)
                                self.assertEqual(redact_credentials(public), public)
                                component = {
                                    "name": "lib",
                                    "version": "1.0",
                                    "description": prefix + value,
                                    "source_info": prefix + value,
                                }
                                for report in self.reports(component):
                                    self.assertNotIn("secret", json.dumps(report))

        for prefix in ("https%3A//", "https%3A%2F%2F", "https:/%2F", "git%2Bssh:/%2F"):
            for separator in ("%3F", "%23", "%2F"):
                value = (
                    prefix + "reader:audit" + separator + "secret%40mirror.example/lib"
                )
                with self.subTest(prefix=prefix, separator=separator):
                    public = redact_credentials(value)
                    self.assertNotIn("secret", public)
                    self.assertIn("mirror.example", public)
                    self.assertEqual(redact_credentials(public), public)
        for url in (
            "https://mirror.example:443/lib@name",
            "https://mirror.example/?email=reader@example.org",
            "https://mirror.example/#email=reader@example.org",
        ):
            for safe in ("", ":", "/", ":/"):
                encoded = quote(url, safe=safe)
                self.assertEqual(redact_credentials(encoded), encoded)

    def test_nested_url_redaction_keeps_private_source_comparisons(self):
        for source in (
            {"remote": "https://git.example/lib.git", "commit": SHA},
            {"source_url": "https://example.org/lib.tar.gz", "checksum": "b" * 64},
        ):
            with self.subTest(source=source):
                info = {
                    "name": "lib",
                    "version": "1.0.0",
                    **source,
                    "remote_patches": {
                        "https://proxy.example/?url=" + quote(PRIVATE): "sha256-patch"
                    },
                }
                changed = {
                    **info,
                    "remote_patches": {
                        url.replace("audit-password", "different-password"): digest
                        for url, digest in info["remote_patches"].items()
                    },
                }
                first = resolve_component(REPO, {"crate_sources": {REPO: info}})
                second = resolve_component(OTHER, {"crate_sources": {OTHER: changed}})
                self.assertEqual(first["source_info"], second["source_info"])
                with self.assertRaisesRegex(
                    ValueError, "Conflicting crate repositories"
                ):
                    deduplicate_components([first, second])

    def test_deep_url_values_are_bounded_without_exposing_credentials(self):
        for encode in (str, quote):
            value = PRIVATE
            for _ in range(80):
                value = "https://proxy.example/?url=" + encode(value)
            public = redact_credentials(value)
            self.assertNotIn("audit-password", public)
            self.assertIn("REDACTED", public)
            self.assertEqual(redact_credentials(public), public)

    def test_unicode_git_tags_keep_valid_distinct_spdx_ids(self):
        components = [
            {
                "name": "lib",
                **git_identity(
                    "unknown",
                    {"remote": "https://github.com/acme/lib.git", "tag": tag},
                ),
            }
            for tag in ("réléase/1", "rêléase/1")
        ]
        document = generate_spdx(components, {}, STAMP)
        packages = document["packages"][1:]
        self.assertEqual(
            {p["versionInfo"] for p in packages}, {"réléase/1", "rêléase/1"}
        )
        ids = {p["SPDXID"] for p in packages}
        self.assertEqual(len(ids), 2)
        for identifier in ids:
            self.assertRegex(identifier, r"^SPDXRef-[A-Za-z0-9.-]+$")
        root_id = document["packages"][0]["SPDXID"]
        for relationship in document["relationships"]:
            self.assertIn(relationship["relatedSpdxElement"], ids | {root_id})

    def test_redaction_preserves_nonsecret_urls_and_is_idempotent(self):
        urls = [
            "https://example.org/lib?file=lib%2Bsrc&download=1#src/lib",
            "ssh://alice@host:2222/~/lib.git",
            "git+https://example.org/repo.git@release%231#src/lib",
            "pkg:github/example/lib@abc123",
            "pkg:generic/lib@1.0?vcs_url="
            + quote("https://example.org/lib?branch=main", safe=""),
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assertEqual(redact_credentials(url), url)
        for scheme in ("http", "https", "git+https", "HTTPs"):
            for host in ("example.org", "[2001:db8::1]:443", "[invalid"):
                for key in (
                    "auth_token",
                    "private-token",
                    "api%5fkey",
                    "X-Goog-Signature",
                    "password",
                ):
                    with self.subTest(scheme=scheme, host=host, key=key):
                        url = f"{scheme}://u:audit-secret@{host}/lib?file=lib&{key}=audit-query#part"
                        result = redact_credentials(url)
                        self.assertNotIn("audit-secret", result)
                        self.assertNotIn("audit-query", result)
                        self.assertIn("file=lib", result)
                        self.assertEqual(redact_credentials(result), result)
                        encoded = "pkg:generic/lib@1.0?vcs_url=" + quote(url, safe="")
                        result = redact_credentials(encoded)
                        self.assertNotIn("audit-secret", result)
                        self.assertNotIn("audit-query", result)
                        self.assertEqual(redact_credentials(result), result)

    def test_registry_errors_do_not_disclose_source_credentials(self):
        url = "https://audit-user:audit-password@registry.example/modules/lib/1.0/source.json"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "MODULE.bazel.lock"
            path.write_text(json.dumps({"registryFileHashes": {url: "bad"}}))
            with self.assertRaises(ValueError) as error:
                registry_source_hashes([str(path)])
            self.assertNotIn("audit-password", str(error.exception))
            path.write_text(json.dumps({"registryFileHashes": {url: "a" * 64}}))
            with self.assertRaises(ValueError) as error:
                parse_module_lockfiles([str(path)], {})
            self.assertNotIn("audit-password", str(error.exception))
            with patch(
                "scripts.generate_registry_metadata_cache.urllib.request.urlopen",
                side_effect=OSError("Unable to fetch " + url),
            ):
                try:
                    registry_cache([str(path)])
                except ValueError:
                    rendered = traceback.format_exc()
                    self.assertNotIn("audit-password", rendered)
                else:
                    self.fail("Fetch failure must propagate")

    def test_patch_commands_publish_fingerprints_and_still_conflict(self):
        for source in (
            {"source_url": PRIVATE, "checksum": "b" * 64},
            {"remote": PRIVATE, "commit": SHA},
        ):
            for field in ("patch_cmds", "patch_cmds_win"):
                with self.subTest(source=source, field=field):
                    info = {
                        "name": "lib",
                        "version": "1.0.0",
                        **source,
                        field: [
                            "curl -H 'Authorization: Bearer inline-secret' https://example.org/fix"
                        ],
                    }
                    component = resolve_component(REPO, {"crate_sources": {REPO: info}})
                    for report in self.reports(component):
                        self.assertNotIn("inline-secret", json.dumps(report))
                        self.assertIn("sha256:", json.dumps(report))
                    different = resolve_component(
                        OTHER,
                        {"crate_sources": {OTHER: {**info, field: ["echo different"]}}},
                    )
                    with self.assertRaisesRegex(
                        ValueError, "Conflicting crate repositories"
                    ):
                        deduplicate_components([component, different])

    def test_raw_cache_roundtrip_keeps_evidence_but_sboms_redact_it(self):
        attrs = {
            "remote": PRIVATE,
            "commit": SHA,
            "remote_patches": PATCHES,
            "init_submodules": True,
        }
        data = {
            "moduleExtensions": {
                "@@rules_rust+//crate_universe:extensions.bzl%crate": {
                    "general": {
                        "generatedRepoSpecs": {
                            "crate_index__lib-1.0.0": {"attributes": attrs}
                        }
                    }
                }
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "MODULE.bazel.lock"
            lock.write_text(json.dumps(data))
            deps = root / "deps.json"
            deps.write_text(json.dumps({"external_repos": [REPO]}))
            with (
                patch(
                    "scripts.generate_crates_metadata_cache.fetch_crate_metadata_from_cratesio",
                    return_value={},
                ),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                cache = generate_cache(
                    module_lock_paths=[str(lock)], deps_path=str(deps)
                )
            cache = json.loads(json.dumps(cache))
            self.assertEqual(
                list(cache["repo:" + REPO]["remote_patches"].items()),
                list(PATCHES.items()),
            )
            component = resolve_component(REPO, {"crates": cache})
            for report in self.reports(component):
                for secret in (
                    "audit-password",
                    "audit-first",
                    "audit-second",
                    "audit-unicode-",
                ):
                    self.assertNotIn(secret, json.dumps(report))

    def test_dotted_git_module_uses_own_metadata_not_parent_inference(self):
        for source in ("git_overrides", "git_repositories"):
            for parent in ("modules", "http_archives", "licenses"):
                for declared, own_license in (
                    (None, ""),
                    ("2.0", ""),
                    ("2.0", "BSD-3-Clause"),
                ):
                    with self.subTest(
                        source=source,
                        parent=parent,
                        declared=declared,
                        license=own_license,
                    ):
                        metadata = {
                            source: {
                                "boost.config": {
                                    "remote": "https://github.com/fork/config.git",
                                    "commit": SHA,
                                }
                            },
                            parent: {
                                "boost": {
                                    "version": "1.87.0",
                                    "license": "MIT",
                                    "supplier": "Parent supplier",
                                }
                            },
                        }
                        if declared:
                            metadata.setdefault("modules", {})["boost.config"] = {
                                "version": declared,
                                "license": own_license,
                            }
                        apply_known_licenses(metadata)
                        component = resolve_component("boost.config+", metadata)
                        self.assertEqual(component["version"], declared or SHA)
                        self.assertEqual(
                            component.get("license", ""),
                            own_license,
                        )
                        enrich_components_from_cpp_cache(
                            [component],
                            [
                                {
                                    "name": "boost",
                                    "version": "1.87.0",
                                    "license": "MIT",
                                    "supplier": "Parent supplier",
                                }
                            ],
                            metadata,
                        )
                        self.assertEqual(
                            component.get("license", ""),
                            own_license,
                        )
                        self.assertNotEqual(
                            component.get("supplier"), "Parent supplier"
                        )
                        metadata.setdefault("licenses", {})["boost.config"] = {
                            "license": "ISC",
                            "purl": "pkg:generic/custom@2.0",
                        }
                        explicit = resolve_component("boost.config+", metadata)
                        self.assertEqual(explicit["license"], "ISC")
                        self.assertEqual(explicit["purl"], "pkg:generic/custom@2.0")


if __name__ == "__main__":
    unittest.main()
