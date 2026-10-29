# *******************************************************************************
# Copyright (c) 2025 Contributors to the Eclipse Foundation
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

load("@score_tooling//python_basics:defs.bzl", "score_py_pytest")
load(":test_module_sources.bzl", "module_sources_test")

package(default_visibility = ["//visibility:private"])

score_py_pytest(
    name = "test_spdx_formatter",
    srcs = ["test_spdx_formatter.py"],
    deps = ["//internal/generator:spdx_formatter"],
)

score_py_pytest(
    name = "test_cyclonedx_formatter",
    srcs = ["test_cyclonedx_formatter.py"],
    deps = ["//internal/generator:cyclonedx_formatter"],
)

score_py_pytest(
    name = "test_bcr_known_licenses",
    srcs = ["test_bcr_known_licenses.py"],
    deps = ["//internal/generator:sbom_generator_lib"],
)

score_py_pytest(
    name = "test_cpp_enrich_checksum",
    srcs = ["test_cpp_enrich_checksum.py"],
    data = ["//:cpp_metadata.json"],
    deps = ["//internal/generator:sbom_generator_lib"],
)

score_py_pytest(
    name = "test_registry_checksums",
    srcs = ["test_registry_checksums.py"],
    data = ["fixtures/boost.config-1.83.0.bcr.4-source.json"],
    deps = [
        "//internal/generator:registry_metadata",
        "//internal/generator:sbom_generator_lib",
        "//scripts:generate_registry_metadata_cache",
    ],
)

score_py_pytest(
    name = "test_sbom_generator",
    srcs = ["test_sbom_generator.py"],
    deps = ["//internal/generator:sbom_generator_lib"],
)

score_py_pytest(
    name = "test_generate_crates_metadata_cache",
    srcs = ["test_generate_crates_metadata_cache.py"],
    deps = ["//scripts:generate_crates_metadata_cache"],
)

score_py_pytest(
    name = "test_generate_python_metadata_cache",
    srcs = ["test_generate_python_metadata_cache.py"],
    deps = ["//scripts:generate_python_metadata_cache_lib"],
)

score_py_pytest(
    name = "test_generate_cpp_metadata_cache",
    srcs = ["test_generate_cpp_metadata_cache.py"],
    deps = ["//scripts:generate_cpp_metadata_cache"],
)

score_py_pytest(
    name = "test_spdx_to_github_snapshot",
    srcs = ["test_spdx_to_github_snapshot.py"],
    deps = ["//scripts:spdx_to_github_snapshot"],
)

score_py_pytest(
    name = "test_real_sbom_integration",
    srcs = ["test_real_sbom_integration.py"],
    data = glob(["fixtures/**"]),
    deps = ["//internal/generator:sbom_generator_lib"],
)

score_py_pytest(
    name = "test_source_metadata",
    srcs = ["test_source_metadata.py"],
    deps = [
        "//internal/generator:sbom_generator_lib",
        "//internal/generator:source_identity",
        "//internal/generator:source_metadata",
        "//scripts:generate_crates_metadata_cache",
    ],
)

module_sources_test(name = "test_module_sources")
