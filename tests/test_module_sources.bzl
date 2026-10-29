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

"""Exercise the module parser in Bazel's actual Starlark interpreter."""

load("//internal:module_sources.bzl", "collect_git_overrides", "parse_module_sources")
load("//internal:rules.bzl", "crate_metadata_inputs")

def _fixture_child(path):
    return path

def _fixture_root(_label):
    return struct(dirname = struct(get_child = _fixture_child))

def _fixture_read(path, watch):
    if watch != "yes":
        fail("Module inputs must be watched")
    return {
        "MODULE.bazel": 'include((("//parts:first.MODULE.bazel")))',
        "parts/first.MODULE.bazel": 'include("//parts:nested.MODULE.bazel")',
        "parts/nested.MODULE.bazel": 'git_override(module_name="lib", remote="https://example.org/lib.git", commit="abc")',
    }[path]

def _module_sources_test_impl(ctx):
    content = """# git_override(module_name="comment", remote="wrong")
TEXT = "git_override(module_name='string', remote='wrong')"
extension.include("//ignored:extension_tag.MODULE.bazel")
extension.git_override(module_name="extension_tag", remote="ignored")
include('//parts:nested.MODULE.bazel')
git_override(
    module_name='score_time',
    remote="https://github.com/eclipse-score/time.git",
    commit="3723ce687e4abc7d6cb4c0efdbbd30455ed7c303", # keep all 40 characters
    patches=["//patches:fix.patch",],
    patch_cmds=['echo ",]"',],
    patch_args=["-p1"],
    remote_patches={"https://example.org/fix.patch": "abc",},
)
"""
    includes, overrides = parse_module_sources(content, "MODULE.bazel")
    if includes != ["//parts:nested.MODULE.bazel"]:
        fail("Unexpected includes: " + str(includes))
    expected = {
        "score_time": {
            "remote": "https://github.com/eclipse-score/time.git",
            "commit": "3723ce687e4abc7d6cb4c0efdbbd30455ed7c303",
            "patches": ["//patches:fix.patch"],
            "patch_cmds": ['echo ",]"'],
            "patch_args": ["-p1"],
            "remote_patches": {"https://example.org/fix.patch": "abc"},
        },
    }
    if overrides != expected:
        fail("Unexpected Git overrides: " + str(overrides))
    if parse_module_sources('module(name="other")', "MODULE.bazel") != ([], {}):
        fail("A module declaration is not an override")
    discovered = collect_git_overrides(struct(path = _fixture_root, read = _fixture_read))
    if discovered != {"lib": {"remote": "https://example.org/lib.git", "commit": "abc"}}:
        fail("Nested includes were not discovered: " + str(discovered))
    expressions = r'''ORG = "qorix-group"
COMMIT = "abc123"
git_override(module_name="dynamic", remote="https://github.com/" + ORG + "/iceoryx2.git", commit=COMMIT,
    patch_cmds=['say \"hi\"', 'echo \x41', 'echo \101', r'echo \path'])
git_override(module_name="partial", remote="https://github.com/" + ORG, commit=COMMIT.lower())
git_override(module_name="UNKNOWN".lower(), remote="https://github.com/example/lib.git", commit="abc")
'''
    _, parsed = parse_module_sources(expressions, "expressions.MODULE.bazel")
    if parsed["dynamic"]["remote"] != "https://github.com/qorix-group/iceoryx2.git" or parsed["dynamic"]["commit"] != "abc123":
        fail("Constants and concatenation must resolve")
    if parsed["dynamic"]["patch_cmds"] != ['say "hi"', "echo A", "echo A", r"echo \path"]:
        fail("Starlark string escapes were not decoded correctly")
    if parsed["partial"]["unresolved_fields"] != ["commit"] or "commit" in parsed["partial"] or "" not in parsed:
        fail("Unsupported expressions must retain partial evidence without failing")
    includes, unresolved = parse_module_sources("include(LABEL.format())", "unresolved.MODULE.bazel")
    if includes or unresolved.get("", {}).get("unresolved_fields") != ["include"]:
        fail("An unresolved include must mark Git discovery incomplete")
    _, grouped = parse_module_sources('git_override(module_name=("lib"), commit=(("abc")))', "grouped.MODULE.bazel")
    if grouped != {"lib": {"commit": "abc"}}:
        fail("Parenthesized literals must retain their values")
    repo = "rules_rust++crate+crate_index__serde-1.0.0"
    manifest = {repo: "external/serde/Cargo.toml"}
    expected_inputs = {"external_repos": [repo], "crate_manifests": manifest}
    if crate_metadata_inputs([repo, "score_a+"], [], manifest) != expected_inputs:
        fail("Only crate metadata belongs in the network action input")
    if crate_metadata_inputs(["score_b+"], ["score_b+::" + repo, "score_b+::score_c+"], manifest) != expected_inputs:
        fail("Unrelated graph changes must not invalidate crate collection")
    if crate_metadata_inputs([], [], {}) == expected_inputs:
        fail("Changes to selected crates must invalidate collection")
    ctx.actions.write(ctx.outputs.executable, "#!/bin/sh\nexit 0\n", is_executable = True)
    return [DefaultInfo(executable = ctx.outputs.executable)]

module_sources_test = rule(implementation = _module_sources_test_impl, test = True)
