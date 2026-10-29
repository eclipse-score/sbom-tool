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

"""Source-backed package identities shared by the SBOM formats."""

import json
import re
import urllib.parse
from typing import Any

from internal.generator.source_metadata import (
    GIT_FIELDS,
    PATCH_FIELDS,
    REGISTRY_SOURCES,
    has_patches,
)


def git_url(remote: str) -> str:
    """Normalize SCP-style SSH remotes to a URI without changing the repository."""
    if "://" not in remote:
        match = re.fullmatch(r"([^/]+@[^/:]+):(.+)", remote)
        if match:
            return "ssh://" + match[1] + "/" + match[2]
    return remote


def git_identity(
    version: str, info: dict[str, Any], cargo: bool = False
) -> dict[str, Any]:
    """Construct source-backed identity without mistaking revisions for checksums."""
    remote = git_url(info.get("remote", ""))
    revision = info.get("commit") or info.get("tag") or ""
    if not cargo and version in ("", "unknown", "0.0.0"):
        version = info.get("tag") or info.get("commit") or "unknown"
    result = {
        "version": version,
        "source": "git",
        "url": remote,
        "purl": "",
        "download_location": "",
    }
    notes = ["Git source: " + remote] if remote else []
    for field in GIT_FIELDS:
        if field != "remote" and info.get(field):
            notes.append(field + ": " + json.dumps(info[field], sort_keys=True))
    if info.get("unresolved_fields"):
        notes.append(
            "Unresolved Git attributes: " + ", ".join(info["unresolved_fields"])
        )
    result["source_info"] = "; ".join(notes)
    source_resolved = not any(
        field in info.get("unresolved_fields", [])
        for field in ("remote", "commit", "tag", "strip_prefix", "**kwargs")
    )
    try:
        parsed = urllib.parse.urlsplit(remote)
        network_remote = bool(
            parsed.hostname
            and parsed.path.strip("/")
            and parsed.scheme.removeprefix("git+") in ("http", "https", "ssh", "git")
        )
    except ValueError:
        network_remote = False
    if not network_remote:
        # Keep local/unsupported remotes in provenance, not as fabricated URLs.
        result["url"] = ""
    if not (network_remote and revision and source_resolved):
        return result

    path = parsed.path.strip("/").removesuffix(".git")
    if parsed.hostname in ("github.com", "gitlab.com") and "/" in path:
        identity = (
            parsed.hostname.split(".")[0]
            + "/"
            + urllib.parse.quote(path.lower(), safe="/")
        )
    else:
        identity = "generic/" + urllib.parse.quote(
            parsed.hostname + "/" + path, safe="/"
        )
    result["purl"] = "pkg:" + identity + "@" + urllib.parse.quote(revision, safe="+")
    location = remote if remote.startswith("git+") else "git+" + remote
    result["download_location"] = location + "@" + revision
    subpath = info.get("strip_prefix", "").strip("/")
    if subpath:
        if any(part in (".", "..") for part in subpath.split("/")):
            raise ValueError("Invalid Git source subdirectory: " + subpath)
        result["purl"] += "#" + urllib.parse.quote(subpath, safe="/")
        result["download_location"] += "#" + subpath
    return result


def crate_source_identity(
    name: str, version: str, info: dict[str, Any]
) -> dict[str, Any]:
    """Use actual crate provenance; absence of provenance is not crates.io proof."""
    source = info.get("source", "")
    if info.get("remote") or source.startswith("git+"):
        if not info.get("remote"):
            parsed = urllib.parse.urlsplit(source[4:])
            info = {
                "remote": urllib.parse.urlunsplit(
                    parsed._replace(query="", fragment="")
                ),
                "commit": parsed.fragment,
            }
        return {**git_identity(version, info, cargo=True), "checksum": ""}
    registry = source in REGISTRY_SOURCES or source == "crates.io"
    result = {
        "source": "crates.io" if registry else "unknown",
        "url": info.get("source_url", "")
        or (
            f"https://crates.io/crates/{name}/{version}"
            if registry and version not in ("", "unknown")
            else ""
        ),
        "purl": f"pkg:cargo/{urllib.parse.quote(name, safe='')}@{urllib.parse.quote(version, safe='+')}"
        if version not in ("", "unknown")
        else "",
    }
    result["checksum"] = info.get("checksum", "")
    if has_patches(info):
        notes = ["Source archive: " + result["url"]] if result["url"] else []
        if result["checksum"]:
            notes.append("SHA256 of unmodified source archive: " + result["checksum"])
        notes.extend(
            field + ": " + json.dumps(info[field], sort_keys=True)
            for field in PATCH_FIELDS
            if info.get(field)
        )
        result["source_info"] = "; ".join(notes)
        result["checksum"] = ""
    return result
