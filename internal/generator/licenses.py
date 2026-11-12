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

"""Declared and concluded licenses for SBOM packages.

SPDX 2.3 gives each package two license fields:

- licenseDeclared (7.15): the license that the package itself states.
- licenseConcluded (7.13): the license that the SBOM producer concluded.

Collectors that read a package's own metadata call ``set_declared_license``.
It stores ``license_declared`` and ``license_declared_source``. Every
collector offers a concluded license with ``set_license``. That stores
``license`` and ``license_source``, and replaces only a license of the same or
a lower priority. The concluded license is the first of:

1. sbom_ext metadata in MODULE.bazel
2. dash-license-scan
3. the declared license
4. the Eclipse S-CORE default or the BCR known-license table

A ``license`` without ``license_source`` comes from older callers. It is
reported as both declared and concluded.
"""

from typing import Any

from internal.generator.utils import _normalize_spdx_license

# Sources of concluded licenses. Any other source is a declaration (priority 2).
USER = "sbom_ext metadata in MODULE.bazel"
DASH = "dash-license-scan"
SCORE_DEFAULT = "the Eclipse S-CORE project default"
BCR_TABLE = "the BCR known-license table"
_PRIORITY = {USER: 0, DASH: 1, SCORE_DEFAULT: 3, BCR_TABLE: 3}
_DECLARED = 2
_NO_LICENSE = 4
SCORE_DEFAULT_LICENSE = "Apache-2.0"

# Sources of declared licenses.
CARGO_MANIFEST = "Cargo.toml"
CRATES_IO = "crates.io registry metadata"
CRATE_CACHE = "the crate metadata cache"
CDXGEN = "the cdxgen source scan"
COMPONENT_LICENSE = "the sbom() component_license attribute"

LICENSE_FIELDS = ("license", "license_source")


def _expression(value: Any) -> str:
    """Return the license expression, or "" when there is none."""
    if not isinstance(value, str) or value.strip().upper() == "NOASSERTION":
        return ""
    return value.strip()


def license_rank(component: dict[str, Any]) -> int:
    """Return the priority of the component's concluded license (lower wins)."""
    if not _expression(component.get("license")):
        return _NO_LICENSE
    return _PRIORITY.get(component.get("license_source", ""), _DECLARED)


def set_license(component: dict[str, Any], expression: Any, source: str) -> None:
    """Offer a concluded license unless one of a higher priority is set."""
    expression = _expression(expression)
    if expression and _PRIORITY.get(source, _DECLARED) <= license_rank(component):
        component["license"] = expression
        component["license_source"] = source


def set_declared_license(
    component: dict[str, Any], expression: Any, source: str
) -> None:
    """Record the license the package states, keeping the first one found."""
    expression = _expression(expression)
    if expression and not component.get("license_declared"):
        component["license_declared"] = expression
        component["license_declared_source"] = source
        set_license(component, expression, source)


def apply_crate_license(component: dict[str, Any], entry: dict[str, Any]) -> None:
    """Apply the licenses of a crate cache entry or a cargo sbom_ext annotation."""
    if "purl_explicit" in entry:
        set_license(component, entry.get("license"), USER)
        return
    source = entry.get("license_source") or ""
    if source == DASH:
        # Caches written before the split stored dash results as `license`.
        set_license(component, entry.get("license"), DASH)
    elif source.startswith("https://"):
        set_declared_license(component, entry.get("license"), CRATES_IO)
    else:
        declared_source = CARGO_MANIFEST if source else CRATE_CACHE
        set_declared_license(component, entry.get("license"), declared_source)
    set_license(component, entry.get("license_concluded"), DASH)


def compare_licenses(declared: str, concluded: str) -> str:
    """Return "matches", "selects" (one of the declared alternatives) or "differs"."""
    declared_terms = _terms(_normalize_spdx_license(declared))
    concluded_terms = _terms(_normalize_spdx_license(concluded))
    if concluded_terms == declared_terms:
        return "matches"
    if (
        declared_terms[0] == " OR "
        and concluded_terms[0] != " AND "
        and concluded_terms[1] < declared_terms[1]
    ):
        return "selects"
    return "differs"


def _terms(expression: str) -> tuple[str, frozenset[str]]:
    """Split a flat AND or OR list so that operand order is not a difference."""
    for operator, other in ((" OR ", " AND "), (" AND ", " OR ")):
        if operator in expression and other not in expression and "(" not in expression:
            return operator, frozenset(expression.split(operator))
    return "", frozenset((expression,))


def root_license(config: dict[str, Any]) -> dict[str, Any]:
    """The root package's author states its license in the sbom() rule."""
    root = {"name": config.get("component_name", "unknown")}
    set_declared_license(root, config.get("component_license", ""), COMPONENT_LICENSE)
    return root


def spdx_license_fields(component: dict[str, Any]) -> dict[str, str]:
    """Return licenseConcluded, licenseDeclared and, if known, licenseComments."""
    concluded = _normalize_spdx_license(_expression(component.get("license")))
    source = component.get("license_source") or ""
    declared = _normalize_spdx_license(_expression(component.get("license_declared")))
    if concluded and not source:
        # A license of unknown origin keeps the earlier output.
        declared = declared or concluded
    if not concluded and str(component.get("name", "")).startswith("score_"):
        concluded, source = SCORE_DEFAULT_LICENSE, SCORE_DEFAULT

    fields = {
        "licenseConcluded": concluded or "NOASSERTION",
        "licenseDeclared": declared or "NOASSERTION",
    }
    error = component.get("license_error", "")
    if not concluded:
        comment = f"No license was found: {error}." if error else ""
    elif source not in _PRIORITY:
        adopted = f"Concluded license adopts the license declared in {source}."
        comment = adopted if source else ""
    elif not declared:
        reason = f": {error}" if error else ""
        comment = f"Concluded from {source}; no declared license was found{reason}."
    else:
        declared_source = component.get("license_declared_source") or "the package"
        declared_in = f"the license declared in {declared_source}"
        comment = {
            "matches": f"Concluded from {source}; matches {declared_in}.",
            "selects": f"Concluded from {source}, which selects from the "
            f"alternatives of {declared_in} ({declared}).",
            "differs": f"Concluded from {source}. This differs from "
            f"{declared_in} ({declared}).",
        }[compare_licenses(declared, concluded)]
    if comment:
        fields["licenseComments"] = comment
    return fields
