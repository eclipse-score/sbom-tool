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

"""Providers for SBOM data propagation.

This module defines the providers used to pass SBOM-related information
between different phases of the build:
- SbomDepsInfo: Collected by aspect - deps of a specific target
- SbomMetadataInfo: Collected by extension - metadata for all modules
"""

# Collected by aspect - deps of a specific target
SbomDepsInfo = provider(
    doc = "Transitive dependency information for SBOM generation",
    fields = {
        "direct_deps": "depset of direct dependency labels",
        "transitive_deps": "depset of all transitive dependency labels",
        "external_repos": "depset of external repository names used",
        "external_dep_edges": "depset of external repo dependency edges (from::to)",
    },
)

# Collected by extension - metadata for all modules
SbomMetadataInfo = provider(
    doc = "Metadata about all available modules/crates",
    fields = {
        "modules": "dict of module_name -> {version, commit, registry, purl}",
        "crates": "dict of crate_name -> {version, checksum, purl}",
        "http_archives": "dict of repo_name -> {url, version, sha256, purl}",
    },
)
