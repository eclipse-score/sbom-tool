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

"""Shared utilities for SBOM generation."""

import hashlib
import json
import re
from collections import Counter
from typing import Any


def component_identity(component: dict[str, Any]) -> tuple[str, str, str]:
    """Keep packages from different ecosystems separate."""
    purl = component.get("purl") or ""
    ecosystem = component.get("ecosystem") or (
        purl[4:].split("/", 1)[0]
        if purl.startswith("pkg:")
        else {
            "crates.io": "cargo",
            "pypi": "pypi",
        }.get((component.get("source") or "").lower(), "")
    )
    return (
        component.get("name", "unknown"),
        component.get("version", "unknown"),
        ecosystem,
    )


def distinct_component_ids(
    ids: dict[tuple[str, str, str], str], reserved: set[str]
) -> dict[tuple[str, str, str], str]:
    """Keep existing IDs unless they collide; use stable suffixes for collisions."""
    counts = Counter(ids.values())
    used = set(ids.values()) | reserved
    result = dict(ids)
    for key, identifier in sorted(ids.items()):
        if counts[identifier] > 1 or identifier in reserved:
            suffix = hashlib.sha256(json.dumps(key).encode()).hexdigest()[:12]
            candidate = identifier + "-" + suffix
            while candidate in used:
                candidate += "-" + suffix
            used.add(candidate)
            result[key] = candidate
    return result


def _normalize_spdx_license(expr: str) -> str:
    """Normalize SPDX boolean operators to uppercase as required by the spec.

    dash-license-scan returns lowercase operators (e.g. 'Apache-2.0 or MIT').
    SPDX 2.3 requires uppercase OR/AND/WITH (Appendix IV).
    Uses space-delimited substitution to avoid modifying license identifiers
    that contain 'or'/'and' as substrings (e.g. GPL-2.0-or-later).
    """
    expr = re.sub(r" or ", " OR ", expr, flags=re.IGNORECASE)
    expr = re.sub(r" and ", " AND ", expr, flags=re.IGNORECASE)
    expr = re.sub(r" with ", " WITH ", expr, flags=re.IGNORECASE)
    return expr
