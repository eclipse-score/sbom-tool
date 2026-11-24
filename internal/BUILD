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

# Internal SBOM implementation package
#
# This package contains internal implementation details for SBOM generation.
# External consumers should use the public API in //:defs.bzl

load("@rules_python//python:defs.bzl", "py_binary")

package(default_visibility = ["//visibility:public"])

exports_files([
    "aspect.bzl",
    "metadata_rule.bzl",
    "module_sources.bzl",
    "providers.bzl",
    "rules.bzl",
])

py_binary(
    name = "export_sbom",
    srcs = ["export_sbom.py"],
    deps = ["@rules_python//python/runfiles"],
)

# Filegroup for all internal bzl files
filegroup(
    name = "bzl_files",
    srcs = [
        "aspect.bzl",
        "metadata_rule.bzl",
        "module_sources.bzl",
        "providers.bzl",
        "rules.bzl",
    ],
)
