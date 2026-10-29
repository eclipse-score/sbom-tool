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

"""SPDX 2.3 JSON formatter for SBOM generation.

This module generates SPDX 2.3 compliant JSON output from the component
information collected by the Bazel aspect and module extension.

SPDX 2.3 Specification: https://spdx.github.io/spdx-spec/v2.3/
"""

import re
import uuid
from typing import Any

from internal.generator.utils import (
    _normalize_spdx_license,
    component_identity,
    distinct_component_ids,
)


def generate_spdx(
    components: list[dict[str, Any]],
    config: dict[str, Any],
    timestamp: str,
    external_dep_edges: list[str] | None = None,
    repository_components: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Generate SPDX 2.3 JSON document.

    Args:
        components: List of component dictionaries
        config: Configuration dictionary with producer info
        timestamp: ISO 8601 timestamp
        external_dep_edges: Bazel repository edges in "source::destination" format
        repository_components: Resolved components keyed by repository name

    Returns:
        SPDX 2.3 compliant dictionary
    """

    namespace = config.get("namespace", "https://eclipse.dev/score")
    component_name = config.get("component_name", "unknown")
    component_version = config.get("component_version", "")
    producer_name = config.get("producer_name", "Eclipse Foundation")
    component_license = _default_score_license(
        component_name, config.get("component_license", "")
    )

    doc_uuid = uuid.uuid4()

    packages: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []

    # Root package
    root_spdx_id = "SPDXRef-RootPackage"
    root_package: dict[str, Any] = {
        "SPDXID": root_spdx_id,
        "name": component_name,
        "versionInfo": component_version if component_version else "unversioned",
        "downloadLocation": "https://github.com/eclipse-score",
        "supplier": f"Organization: {producer_name}",
        "primaryPackagePurpose": "APPLICATION",
        "filesAnalyzed": False,
        "licenseConcluded": component_license or "NOASSERTION",
        "licenseDeclared": component_license or "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }
    packages.append(root_package)

    # DESCRIBES relationship
    relationships.append(
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_spdx_id,
        }
    )

    dependency_packages = [_create_spdx_package(comp) for comp in components]
    component_ids = distinct_component_ids(
        {
            component_identity(comp): spdx_id
            for comp, (_, spdx_id) in zip(components, dependency_packages)
        },
        {root_spdx_id, "SPDXRef-DOCUMENT"},
    )

    # Add dependency packages
    for comp, (pkg, _) in zip(components, dependency_packages):
        spdx_id = component_ids[component_identity(comp)]
        pkg["SPDXID"] = spdx_id
        packages.append(pkg)

        # Root depends on each component
        relationships.append(
            {
                "spdxElementId": root_spdx_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": spdx_id,
            }
        )

    # Match the ecosystem and version when resolving dependency edges.
    repository_ids = {
        repo.rstrip("+"): component_ids.get(
            component_identity(comp),
            root_spdx_id
            if comp.get("name") == component_name
            and component_identity(comp)[2] not in ("cargo", "pypi")
            else None,
        )
        for repo, comp in (repository_components or {}).items()
    }
    seen_edges = {(r["spdxElementId"], r["relatedSpdxElement"]) for r in relationships}
    for edge in sorted(set(external_dep_edges or [])):
        if "::" not in edge:
            continue
        src, dst = edge.split("::", 1)
        src_id = repository_ids.get(src.rstrip("+"))
        dst_id = repository_ids.get(dst.rstrip("+"))
        if (
            not src_id
            or not dst_id
            or src_id == dst_id
            or (src_id, dst_id) in seen_edges
        ):
            continue
        relationships.append(
            {
                "spdxElementId": src_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": dst_id,
            }
        )
        seen_edges.add((src_id, dst_id))

    # Collect LicenseRef-* identifiers used in packages and declare them
    extracted = _collect_extracted_license_infos(packages)

    doc: dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"SBOM for {component_name}",
        "documentNamespace": f"{namespace}/spdx/{_sanitize_id(component_name)}-{doc_uuid}",
        "creationInfo": {
            "created": timestamp,
            "creators": [
                f"Organization: {producer_name}",
                "Tool: score-sbom-generator",
            ],
        },
        "packages": packages,
        "relationships": relationships,
    }

    if extracted:
        doc["hasExtractedLicensingInfos"] = extracted

    return doc


def _create_spdx_package(
    component: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    """Create an SPDX 2.3 Package for a component.

    Args:
        component: Component dictionary

    Returns:
        Tuple of (SPDX Package dictionary, spdx_id string)
    """
    name = component.get("name", "unknown")
    version = component.get("version", "unknown")
    purl = component.get("purl", "")
    if purl.split("?", 1)[0].split("#", 1)[0].endswith("@unknown"):
        purl = ""
    license_id = _default_score_license(name, component.get("license", ""))
    description = component.get("description", "")
    supplier = component.get("supplier", "")
    comp_type = component.get("type", "library")
    checksum = component.get("checksum", "")

    spdx_id = f"SPDXRef-{_sanitize_id(name)}-{_sanitize_id(version)}"

    # Determine download location
    url = component.get("download_location") or component.get("url", "")
    source = component.get("source", "")
    if source == "git":
        download_location = component.get("download_location") or "NOASSERTION"
    elif url:
        download_location = url
    elif source == "crates.io" and version not in ("", "unknown"):
        download_location = f"https://crates.io/crates/{name}/{version}"
    else:
        download_location = "NOASSERTION"

    package: dict[str, Any] = {
        "SPDXID": spdx_id,
        "name": name,
        "downloadLocation": download_location,
        "primaryPackagePurpose": _map_type_to_purpose(comp_type),
        "filesAnalyzed": False,
        "licenseConcluded": license_id if license_id else "NOASSERTION",
        "licenseDeclared": license_id if license_id else "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }

    if version not in ("", "unknown"):
        package["versionInfo"] = version
    if component.get("source_info"):
        package["sourceInfo"] = component["source_info"]

    if checksum:
        package["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]

    if description:
        package["description"] = description

    if supplier:
        package["supplier"] = f"Organization: {supplier}"

    # Add PURL as external reference
    if purl:
        package["externalRefs"] = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            },
        ]

    return package, spdx_id


def _default_score_license(name: str, license_id: str) -> str:
    """Use the SCORE default license when a score module has no metadata."""
    normalized = _normalize_spdx_license(license_id)
    if not normalized and name.startswith("score_"):
        return "Apache-2.0"
    return normalized


def _map_type_to_purpose(comp_type: str) -> str:
    """Map component type to SPDX 2.3 primary package purpose."""
    type_mapping = {
        "application": "APPLICATION",
        "library": "LIBRARY",
        "framework": "FRAMEWORK",
        "file": "FILE",
        "container": "CONTAINER",
        "firmware": "FIRMWARE",
        "device": "DEVICE",
        "data": "DATA",
    }
    return type_mapping.get(comp_type, "LIBRARY")


def _collect_extracted_license_infos(
    packages: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Collect LicenseRef-* identifiers from packages and build declarations.

    SPDX requires every LicenseRef-* used in license expressions to be
    declared in hasExtractedLicensingInfos.

    Args:
        packages: List of SPDX package dicts

    Returns:
        List of extractedLicensingInfo entries
    """
    license_refs: set[str] = set()
    pattern = re.compile(r"LicenseRef-[A-Za-z0-9\-.]+")

    for pkg in packages:
        for field in ("licenseConcluded", "licenseDeclared"):
            value = pkg.get(field, "")
            license_refs.update(pattern.findall(value))

    return [
        {
            "licenseId": ref,
            "extractedText": f"See package metadata for license details ({ref})",
        }
        for ref in sorted(license_refs)
    ]


def _sanitize_id(value: str) -> str:
    """Sanitize a string for use in SPDX IDs.

    SPDX 2.3 IDs must match [a-zA-Z0-9.-]+
    """
    result = []
    for char in value:
        if char.isalnum() or char in (".", "-"):
            result.append(char)
        elif char in ("_", " ", "/", "@"):
            result.append("-")
    return "".join(result) or "unknown"
