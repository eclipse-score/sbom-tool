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
import hashlib
import re
import urllib.parse
from typing import Any

from internal.generator.reporting import redact_credentials

from internal.generator.source_metadata import (
    GIT_FIELDS,
    PATCH_FIELDS,
    REGISTRY_SOURCES,
    git_checkout_settings,
    git_source_fingerprint,
    git_url,
    has_patches,
    patch_identity,
)


def git_identity(
    version: str, info: dict[str, Any], cargo: bool = False
) -> dict[str, Any]:
    """Construct source-backed identity without mistaking revisions for checksums."""
    info = {**info, **git_checkout_settings(info)}
    original_remote = git_url(info.get("remote", ""))
    remote = redact_credentials(original_remote)
    commit = info.get("commit") or ""
    revision = commit or info.get("tag") or ""
    if not cargo and version in ("", "unknown", "0.0.0"):
        version = info.get("tag") or info.get("commit") or "unknown"
    result = {
        "version": version,
        "source": "git",
        "url": remote,
        "purl": "",
        "download_location": "",
        # Tags and abbreviated/symbolic revisions cannot prove equal checkouts.
        "git_commit": commit
        if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", commit)
        else "",
    }
    notes = ["Git source: " + original_remote] if original_remote else []
    for field in GIT_FIELDS:
        if field != "remote" and info.get(field):
            notes.append(_source_note(field, info[field]))
    if info.get("unresolved_fields"):
        notes.append(
            "Unresolved Git attributes: " + ", ".join(info["unresolved_fields"])
        )
    original_notes = "; ".join(notes)
    # Private comparison evidence must survive reporting redaction, including
    # authenticated patch URLs that redact to the same public URL.
    result["source_fingerprint"] = git_source_fingerprint(info)
    result["source_info"] = redact_credentials(original_notes)
    source_resolved = not any(
        field in info.get("unresolved_fields", [])
        for field in ("remote", "commit", "tag", "strip_prefix", "**kwargs")
    )
    try:
        parsed = urllib.parse.urlsplit(remote)
        port = parsed.port  # Validate ports before emitting a network identity.
        scheme = parsed.scheme.removeprefix("git+")
        network_remote = bool(
            parsed.hostname
            and parsed.path.strip("/")
            and scheme in ("http", "https", "ssh", "git")
        )
    except ValueError:
        network_remote = False
    if not network_remote:
        # Keep local/unsupported remotes in provenance, not as fabricated URLs.
        result["url"] = ""
    if not (network_remote and revision and source_resolved):
        return result

    path = urllib.parse.unquote(parsed.path).strip("/")
    if scheme == "ssh" and path.startswith("~/") and parsed.username:
        # Each SSH login can have a different home repository at the same path.
        path = "~" + urllib.parse.unquote(parsed.username) + "/" + path[2:]
    default_port = {"http": 80, "https": 443, "ssh": 22, "git": 9418}[scheme]
    if (
        parsed.hostname in ("github.com", "gitlab.com")
        and port in (None, default_port)
        and "/" in path
        and not path.startswith("~")
    ):
        identity = (
            parsed.hostname.split(".")[0]
            + "/"
            + urllib.parse.quote(path.lower().removesuffix(".git"), safe="/")
        )
    else:
        authority = parsed.hostname
        if port is not None:
            if ":" in authority:  # Bracket IPv6 to distinguish its port.
                authority = "[" + authority + "]"
            authority += ":" + str(port)
        identity = "generic/" + urllib.parse.quote(authority + "/" + path, safe="/")
    encoded_revision = urllib.parse.quote(revision, safe="+")
    result["purl"] = "pkg:" + identity + "@" + encoded_revision
    location = parsed._replace(
        scheme="git+" + scheme,
        path=parsed.path + "@" + encoded_revision,
        fragment="",
    )
    result["download_location"] = urllib.parse.urlunsplit(location)
    subpath = info.get("strip_prefix", "").strip("/")
    if subpath:
        if any(part in (".", "..") for part in subpath.split("/")):
            raise ValueError("Invalid Git source subdirectory: " + subpath)
        encoded_subpath = urllib.parse.quote(subpath, safe="/")
        result["purl"] += "#" + encoded_subpath
        result["download_location"] += "#" + encoded_subpath
    return result


def _source_note(field: str, value: Any) -> str:
    if field in ("patch_cmds", "patch_cmds_win"):
        # Commands can embed arbitrary credentials, not just recognizable URLs.
        value = [
            "sha256:" + hashlib.sha256(command.encode()).hexdigest()
            for command in value
        ]
    elif field == "remote_patches":
        # Distinct authenticated URLs may redact to the same public URL.
        value = list(value.items())
    return field + ": " + json.dumps(value)


def crate_source_identity(
    name: str, version: str, info: dict[str, Any]
) -> dict[str, Any]:
    """Use actual crate provenance; absence of provenance is not crates.io proof."""
    source = info.get("source", "")
    if info.get("remote") or source.startswith("git+"):
        if not info.get("remote"):
            parsed = urllib.parse.urlsplit(source[4:])
            info = {
                **info,
                "remote": urllib.parse.urlunsplit(
                    parsed._replace(query="", fragment="")
                ),
                "commit": parsed.fragment,
            }
        return {
            **git_identity(version, info, cargo=True),
            "checksum": "",
            "archive_source": {},  # Clear any archive evidence from a legacy cache.
        }
    registry = source in REGISTRY_SOURCES or source == "crates.io"
    result = {
        "source": "crates.io" if registry else "unknown",
        # Return a complete identity so replacing cached Git/patched sources
        # cannot leave their location or provenance attached to an archive.
        "download_location": "",
        "source_info": "",
        "git_commit": "",
        "url": redact_credentials(info.get("source_url", ""))
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
    # Deduplication needs the input archive and transformations, independently of
    # the emitted package hash and human-readable provenance (which includes mirrors).
    result["archive_source"] = {
        "checksum": result["checksum"],
        "strip_prefix": info.get("strip_prefix", ""),
    }
    if has_patches(info):
        result["archive_source"].update(patch_identity(info))
        notes = ["Source archive: " + result["url"]] if result["url"] else []
        if result["checksum"]:
            notes.append("SHA256 of unmodified source archive: " + result["checksum"])
        notes.extend(
            _source_note(field, info[field])
            for field in PATCH_FIELDS
            if info.get(field)
        )
        result["source_info"] = redact_credentials("; ".join(notes))
        result["checksum"] = ""
    return result
