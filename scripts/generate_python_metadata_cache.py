#!/usr/bin/env python3
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

"""Collect Python package metadata from pip-compile lockfiles."""

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


PACKAGE_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9_.-]*)\[.*\]==([^\s\\]+)|^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s\\]+)"
)
HASH_RE = re.compile(r"--hash=sha256[=:]([0-9a-fA-F]{64})")


def _find_uvx() -> str:
    """Locate uvx in PATH or in the standard user installation directory."""
    return shutil.which("uvx") or str(Path.home() / ".local/bin/uvx")


def parse_requirements_lockfile(path: str) -> dict[str, dict[str, str]]:
    """Parse pinned packages and hashes from a pip-compile lockfile."""
    packages: dict[str, dict[str, str]] = {}
    pending_name = ""
    pending_version = ""
    pending_hashes: list[str] = []

    def store() -> None:
        if not pending_name or not pending_version:
            return
        entry = {
            "name": pending_name,
            "version": pending_version,
            "purl": f"pkg:pypi/{pending_name.lower().replace('_', '-')}@{pending_version}",
            "license": "NOASSERTION",
            "description": "Missing",
            "supplier": "",
            "source": "PyPI",
        }
        if pending_hashes:
            entry["checksum"] = pending_hashes[0].lower()
        packages[pending_name.lower().replace("_", "-")] = entry

    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        match = PACKAGE_RE.match(line)
        if match:
            store()
            pending_name = match.group(1) or match.group(3)
            pending_version = match.group(2) or match.group(4)
            pending_hashes = HASH_RE.findall(line)
        elif pending_name:
            pending_hashes.extend(HASH_RE.findall(line))
        if not line.endswith("\\"):
            store()
            pending_name = ""
            pending_version = ""
            pending_hashes = []

    store()
    return packages


def run_dash_license_scan(lockfiles: list[str], summary_path: str) -> bool:
    """Run DASH license scanning for Python lockfiles.

    The dash-license-scan wrapper converts requirements files to DASH PURLs and
    writes the checker summary as CSV. Restricted or unverified packages are
    reported by DASH with a non-zero status, but the summary remains usable.
    """
    cache_dir = tempfile.mkdtemp(prefix="dash-license-scan-")
    env = os.environ.copy()
    env["UV_CACHE_DIR"] = cache_dir
    env["UV_TOOL_DIR"] = cache_dir
    command = [
        _find_uvx(),
        "--from",
        "dash-license-scan@git+https://github.com/eclipse-score/dash-license-scan",
        "dash-license-scan",
        "--summary",
        summary_path,
        *lockfiles,
    ]
    try:
        result = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
            timeout=600,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"WARNING: DASH Python license scan unavailable: {error}")
        return False
    if result.returncode < 0:
        print(f"WARNING: DASH Python license scan was terminated: {result.returncode}")
        return False
    if result.returncode != 0 and result.stderr:
        print(
            f"WARNING: DASH Python license scan reported errors: {result.stderr.strip()}"
        )
    return Path(summary_path).is_file()


def parse_dash_summary(summary_path: str) -> dict[str, str]:
    """Parse DASH summary rows into a normalized PyPI-name/license lookup."""
    licenses: dict[str, str] = {}
    for raw_line in Path(summary_path).read_text(encoding="utf-8").splitlines():
        parts = [part.strip() for part in raw_line.split(",")]
        if len(parts) < 2:
            continue
        identifier, license_expression = parts[0], parts[1]
        identifier_parts = identifier.split("/")
        if (
            len(identifier_parts) >= 5
            and identifier_parts[0:3] == ["pypi", "pypi", "-"]
            and license_expression
        ):
            licenses[identifier_parts[3].lower().replace("_", "-")] = license_expression
    return licenses


def enrich_python_licenses(
    packages: dict[str, dict[str, str]], lockfiles: list[str]
) -> None:
    """Enrich parsed Python packages with SPDX expressions returned by DASH."""
    with tempfile.TemporaryDirectory(prefix="python-dash-") as temp_dir:
        summary_path = str(Path(temp_dir) / "summary.csv")
        if not run_dash_license_scan(lockfiles, summary_path):
            return
        for package_name, license_expression in parse_dash_summary(
            summary_path
        ).items():
            if package_name in packages:
                packages[package_name]["license"] = license_expression


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    parser.add_argument("lockfiles", nargs="+")
    parser.add_argument(
        "--skip-dash",
        action="store_true",
        help="Skip DASH license enrichment (for offline builds)",
    )
    args = parser.parse_args()

    packages: dict[str, dict[str, str]] = {}
    for lockfile in args.lockfiles:
        packages.update(parse_requirements_lockfile(lockfile))
    if not args.skip_dash:
        enrich_python_licenses(packages, args.lockfiles)
    Path(args.output).write_text(json.dumps(packages, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
