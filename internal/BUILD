# Internal SBOM implementation package
#
# This package contains internal implementation details for SBOM generation.
# External consumers should use the public API in //:defs.bzl

package(default_visibility = ["//visibility:public"])

exports_files([
    "aspect.bzl",
    "metadata_rule.bzl",
    "providers.bzl",
    "rules.bzl",
])

# Filegroup for all internal bzl files
filegroup(
    name = "bzl_files",
    srcs = [
        "aspect.bzl",
        "metadata_rule.bzl",
        "providers.bzl",
        "rules.bzl",
    ],
)
