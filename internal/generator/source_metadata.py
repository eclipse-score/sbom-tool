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

"""Bazel crate source metadata shared by the collector and SBOM generator."""

import json
import re
import sys
import urllib.parse
from typing import Any

GIT_FIELDS = (
    "remote",
    "commit",
    "tag",
    "strip_prefix",
    "patches",
    "patch_args",
    "patch_cmds",
    "patch_cmds_win",
    "patch_tool",
    "patch_strip",
    "remote_patches",
    "remote_patch_strip",
)
REGISTRY_SOURCES = (
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
)
PATCH_FIELDS = GIT_FIELDS[4:]


def has_patches(info: dict[str, Any]) -> bool:
    return any(
        info.get(k)
        for k in ("patches", "remote_patches", "patch_cmds", "patch_cmds_win")
    )


def read_module_lockfiles(paths: list[str]) -> dict[str, dict[str, Any]]:
    """Read each lockfile once; report unusable optional metadata consistently."""
    result = {}
    for path in dict.fromkeys(paths):
        try:
            with open(path, encoding="utf-8") as stream:
                data = json.load(stream)
            if not isinstance(data, dict):
                raise ValueError("expected a JSON object")
        except (OSError, ValueError) as exc:
            print(f"WARNING: Skipping lockfile {path}: {exc}", file=sys.stderr)
            continue
        result[path] = data
    return result


def _merge_source(crates: dict[str, dict[str, Any]], info: dict[str, Any]) -> None:
    """Reject different contents, revisions or modifications, not mirror spelling."""
    repository = info["repository"]
    previous = crates.get(repository)
    if previous is None:
        crates[repository] = dict(info)
        return
    versions_match = previous["version"] == info["version"] or (
        (previous["version_from_repository"] or info["version_from_repository"])
        and previous["version"].replace("+", "-") == info["version"].replace("+", "-")
    )
    fields = ("name", "remote", "commit", "tag", "strip_prefix")
    same = versions_match and all(
        previous.get(k, "") == info.get(k, "") for k in fields
    )
    if has_patches(previous) or has_patches(info):
        same = same and {k: previous[k] for k in PATCH_FIELDS if previous.get(k)} == {
            k: info[k] for k in PATCH_FIELDS if info.get(k)
        }
    if not info.get("remote"):
        if previous.get("checksum") and info.get("checksum"):
            same = same and previous["checksum"] == info["checksum"]
        else:
            same = same and previous.get("source_url") == info.get("source_url")
    if not same:
        raise ValueError(f"Conflicting crate sources for {repository}")
    # Keep authoritative version spelling and stable mirror selection.
    if not info["version_from_repository"]:
        previous["version"] = info["version"]
        previous["version_from_repository"] = False
    previous["source_url"] = min(
        (url for url in (previous.get("source_url"), info.get("source_url")) if url),
        default="",
    )
    previous["checksum"] = previous.get("checksum") or info.get("checksum", "")
    if previous["source"] != info["source"]:
        # Matching checksums/patches above establish equivalent contents even
        # when only one entry identifies the original crates.io archive.
        previous["source"] = (
            REGISTRY_SOURCES[0]
            if previous["source"] in REGISTRY_SOURCES
            or info["source"] in REGISTRY_SOURCES
            else "module-bazel-lock"
        )


def parse_module_bazel_locks(
    paths: list[str], *, lockfiles: dict[str, dict[str, Any]] | None = None
) -> dict[str, dict[str, Any]]:
    """Share source parsing and conflict checks across both consumers."""
    if lockfiles is None:
        lockfiles = read_module_lockfiles(paths)
    crates = {}
    for data in lockfiles.values():
        for info in _crate_sources(data).values():
            _merge_source(crates, info)
    return crates


def parse_module_bazel_lock(lockfile_path: str) -> dict[str, dict[str, Any]]:
    """Read crate sources from every extension and platform in a Bazel lockfile."""
    return parse_module_bazel_locks([lockfile_path])


def _crate_sources(lock_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    crates = {}
    for ext_key, extension in lock_data.get("moduleExtensions", {}).items():
        if "crate" not in ext_key.lower():
            continue
        for variant in extension.values():
            specs = variant.get("generatedRepoSpecs", {})
            for repo_name, spec in specs.items():
                # Crate repositories use <hub>__<name>-<version>; skip the hub itself.
                if "__" not in repo_name:
                    continue

                crate_part = repo_name.split("__", 1)[1]

                # Parse name-version (e.g., "serde-1.0.228", "iceoryx2-qnx8-0.7.0")
                m = re.match(r"^(.+?)-(\d+\.\d+\.\d+.*)$", crate_part)
                if not m:
                    continue

                name = m.group(1)
                version = m.group(2)
                attrs = spec.get("attributes", {})
                sha256 = attrs.get("sha256", "")
                archive_prefix = attrs.get("strip_prefix", "")
                exact_version = archive_prefix.removeprefix(name + "-")
                version_from_repository = True
                if (
                    archive_prefix.startswith(name + "-")
                    and exact_version.replace("+", "-") == version
                ):
                    version = exact_version
                    version_from_repository = False

                repository = (
                    ext_key.split("//")[0].lstrip("@")
                    + "+"
                    + ext_key.rsplit("%", 1)[-1]
                    + "+"
                    + repo_name
                )
                info = {
                    "name": name,
                    "version": version,
                    "version_from_repository": version_from_repository,
                    "checksum": sha256,
                    "source": (
                        REGISTRY_SOURCES[0]
                        if _is_cratesio_archive(attrs, name, version)
                        else ("git" if attrs.get("remote") else "module-bazel-lock")
                    ),
                    "repository": repository,
                }

                info.update({key: attrs[key] for key in GIT_FIELDS if key in attrs})
                if not has_patches(info):
                    for field in PATCH_FIELDS:
                        info.pop(field, None)
                urls = attrs.get("urls", []) or [attrs.get("url", "")]
                info["source_url"] = attrs.get("remote", "") or urls[0]
                if info.get("remote"):
                    info["checksum"] = ""
                _merge_source(crates, info)
    return crates


def _is_cratesio_archive(attrs: dict[str, Any], name: str, version: str) -> bool:
    """Only permit API fallback for a matching, unpatched crates.io archive."""
    if attrs.get("remote") or has_patches(attrs):
        return False
    paths = {
        ("static.crates.io", f"/crates/{name}/{version}/download"),
        ("static.crates.io", f"/crates/{name}/{name}-{version}.crate"),
        ("crates.io", f"/api/v1/crates/{name}/{version}/download"),
    }
    urls = attrs.get("urls", []) or [attrs.get("url", "")]
    return bool(urls) and all(
        (parsed.scheme == "https" and (parsed.netloc, parsed.path) in paths)
        for parsed in map(urllib.parse.urlsplit, urls)
    )
