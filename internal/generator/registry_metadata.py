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

"""Check Bazel registry metadata and read archive checksums."""

import base64
import binascii
import hashlib
import json
import re


def archive_metadata(source_text: str, expected_sha256: str) -> dict[str, str]:
    """Check source.json against the lockfile, then read the archive URL and hash.

    Return no checksum for other source types or hashes other than SHA-256.
    Raise ValueError if the metadata or SHA-256 value is invalid.
    """
    if not isinstance(source_text, str):
        raise ValueError("Registry cache must contain the original source.json text")
    actual = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    if actual != expected_sha256:
        raise ValueError("Registry source.json SHA-256 does not match the lockfile")
    source = json.loads(source_text)
    if not isinstance(source, dict):
        raise ValueError("Registry source.json must be an object")
    if source.get("type", "archive") != "archive":
        return {}
    url = source.get("url")
    if not isinstance(url, str) or not url:
        raise ValueError("Registry archive source.json must identify its archive URL")
    integrity = source.get("integrity", "")
    if not isinstance(integrity, str):
        raise ValueError("Registry archive integrity must be a string")
    if not integrity.startswith("sha256-"):
        return {"url": url}
    try:
        digest = base64.b64decode(integrity[len("sha256-") :], validate=True)
    except binascii.Error as exc:
        raise ValueError("Invalid SHA-256 archive integrity encoding") from exc
    if len(digest) != 32:
        raise ValueError("SHA-256 archive integrity must contain 32 bytes")
    return {"sha256": digest.hex(), "url": url}


def registry_source_hashes(lockfiles: list[str]) -> dict[str, str]:
    """Read source.json URLs and hashes from the lockfiles."""
    sources: dict[str, str] = {}
    for path in lockfiles:
        with open(path, encoding="utf-8") as lockfile:
            hashes = json.load(lockfile).get("registryFileHashes", {})
        for url, digest in hashes.items():
            if not re.search(r"/modules/[^/]+/[^/]+/source\.json$", url):
                continue
            if digest == "not found":
                continue
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError(f"Invalid registry metadata SHA-256 for {url}")
            if url in sources and sources[url] != digest:
                raise ValueError(f"Conflicting registry metadata hashes for {url}")
            sources[url] = digest
    return sources
