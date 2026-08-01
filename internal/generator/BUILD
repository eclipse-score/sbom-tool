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

# SBOM Generator Python package
#
# This package contains the Python tools for generating SBOM files
# in SPDX 2.3 and CycloneDX 1.6 formats.

load("@rules_python//python:defs.bzl", "py_binary", "py_library")

package(default_visibility = ["//visibility:public"])

py_binary(
    name = "sbom_generator",
    srcs = ["sbom_generator.py"],
    main = "sbom_generator.py",
    deps = [
        ":cyclonedx_formatter",
        ":spdx_formatter",
    ],
)

py_library(
    name = "sbom_generator_lib",
    srcs = ["sbom_generator.py"],
    deps = [
        ":cyclonedx_formatter",
        ":spdx_formatter",
    ],
)

py_library(
    name = "utils",
    srcs = ["utils.py"],
)

py_library(
    name = "spdx_formatter",
    srcs = ["spdx_formatter.py"],
    deps = [":utils"],
)

py_library(
    name = "cyclonedx_formatter",
    srcs = ["cyclonedx_formatter.py"],
    deps = [":utils"],
)
