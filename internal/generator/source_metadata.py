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

import hashlib
import json
import re
import sys
import urllib.parse
from typing import Any

PATCH_FIELDS = (
    "patches",
    "patch_args",
    "patch_cmds",
    "patch_cmds_win",
    "patch_tool",
    "patch_strip",
    "remote_patches",
    "remote_patch_strip",
)
GIT_FIELDS = (
    "remote",
    "commit",
    "tag",
    "strip_prefix",
    "init_submodules",
    "recursive_init_submodules",
    *PATCH_FIELDS,
)
REGISTRY_SOURCES = (
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
)


def git_url(remote: str) -> str:
    """Normalize SCP-style SSH remotes to a URI without changing the repository."""
    # Windows drive paths are local, even though they contain a colon.
    if "://" not in remote and not re.match(r"^[A-Za-z]:", remote):
        match = re.fullmatch(
            r"((?:[^/@:\\\s]+@)?(?:\[[^\]\s]+\]|[^/@:\\\s\[\]]+)):([^:].*)", remote
        )
        if match:
            authority, path = match.groups()
            host = authority.rsplit("@", 1)[-1].lower()
            # Public hosting uses project paths; ordinary SSH paths are relative
            # to the login user's home unless they begin with '/' or '~'.
            if not path.startswith(("/", "~")) and host not in (
                "github.com",
                "gitlab.com",
            ):
                path = "~/" + path
            return (
                "ssh://"
                + authority
                + ("" if path.startswith("/") else "/")
                + urllib.parse.quote(path, safe="/~")
            )
    return remote


def git_source_fingerprint(info: dict[str, Any]) -> str:
    """Compare private checkout evidence, independently of reporting/annotations."""
    remote = git_url(info.get("remote", ""))
    try:
        parsed = urllib.parse.urlsplit(remote)
        scheme = parsed.scheme.removeprefix("git+")
        default_port = {"http": 80, "https": 443, "ssh": 22, "git": 9418}.get(scheme)
        path = parsed.path.rstrip("/")
        # Only GitHub's project URLs are known aliases here. On arbitrary
        # servers and local paths, repo and repo.git may be different sources.
        if (
            parsed.hostname == "github.com"
            and default_port is not None
            and parsed.port in (None, default_port)
            and len(path.split("/")) == 3
            and all(path.split("/")[1:])
        ):
            # Normalize the known endpoint, retaining private userinfo verbatim.
            userinfo, separator, _ = parsed.netloc.rpartition("@")
            remote = urllib.parse.urlunsplit(
                parsed._replace(
                    netloc=userinfo + separator + parsed.hostname,
                    path=path.lower().removesuffix(".git"),
                )
            )
    except ValueError:
        pass  # Keep malformed/unsupported remotes as exact private evidence.
    evidence = {
        "remote": remote,
        "commit": info.get("commit", ""),
        "tag": info.get("tag", ""),
        "strip_prefix": info.get("strip_prefix", ""),
        **git_checkout_settings(info),
        "patches": patch_identity(info) if has_patches(info) else {},
        "unresolved_fields": sorted(info.get("unresolved_fields", [])),
    }
    return hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()


def git_checkout_settings(info: dict[str, Any]) -> dict[str, bool]:
    """Normalize Bazel's defaults; recursive checkout takes precedence."""
    recursive = bool(info.get("recursive_init_submodules"))
    return {
        "init_submodules": bool(info.get("init_submodules")) and not recursive,
        "recursive_init_submodules": recursive,
    }


def has_patches(info: dict[str, Any]) -> bool:
    return any(
        info.get(k)
        for k in ("patches", "remote_patches", "patch_cmds", "patch_cmds_win")
    )


def patch_identity(info: dict[str, Any]) -> dict[str, Any]:
    """Compare patch inputs in application order, including remote patch maps."""
    result = {field: info[field] for field in PATCH_FIELDS if info.get(field)}
    if info.get("remote_patches"):
        result["remote_patches"] = list(info["remote_patches"].items())
    return result


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
    same = versions_match and previous["name"] == info["name"]
    if previous.get("remote") or info.get("remote"):
        same = same and git_source_fingerprint(previous) == git_source_fingerprint(info)
    else:
        same = same and all(
            previous.get(k, "") == info.get(k, "")
            for k in ("commit", "tag", "strip_prefix")
        )
        if has_patches(previous) or has_patches(info):
            same = same and patch_identity(previous) == patch_identity(info)
        if previous.get("checksum") or info.get("checksum"):
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
