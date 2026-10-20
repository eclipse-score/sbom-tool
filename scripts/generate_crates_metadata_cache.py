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

"""Generate crates metadata cache for SBOM generation.

This script parses Cargo.lock files and/or MODULE.bazel.lock files for
crate version/checksum data, fetches metadata from crates.io, and creates
a cache file for SBOM generation. Optional dash-license-scan integration
can be enabled via CLI for environments that require it.

Usage:
    python3 generate_crates_metadata_cache.py <output.json> --module-lock <MODULE.bazel.lock>
    python3 generate_crates_metadata_cache.py <output.json> --cargo-lock <Cargo.lock>
    python3 generate_crates_metadata_cache.py <output.json> --cargo-lock <Cargo.lock> --module-lock <MODULE.bazel.lock>

Example:
    python3 generate_crates_metadata_cache.py crates_metadata.json \\
        --module-lock ../../score-crates/MODULE.bazel.lock
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import http.client
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:
    import tomli as tomllib


def parse_cargo_lock(lockfile_path: str) -> dict[str, dict[str, Any]]:
    """Parse Cargo.lock and extract crate information.

    Args:
        lockfile_path: Path to Cargo.lock file

    Returns:
        Dict mapping name@version to {version, checksum, source}
    """
    with open(lockfile_path, "rb") as f:
        lock_data = tomllib.load(f)

    crates = {}
    for package in lock_data.get("package", []):
        name = package["name"]
        source = package.get("source", "")

        # Only include crates from crates.io
        if "registry+https://github.com/rust-lang/crates.io-index" in source:
            crates[f"{name}@{package['version']}"] = {
                "name": name,
                "version": package["version"],
                "checksum": package.get("checksum", ""),
                "source": source,
            }

    return crates


def parse_module_bazel_lock(lockfile_path: str) -> dict[str, dict[str, Any]]:
    """Parse MODULE.bazel.lock and extract crate information from cargo-bazel resolution.

    The MODULE.bazel.lock (from score_crates or similar) contains resolved crate
    specs under moduleExtensions -> crate_universe -> generatedRepoSpecs.
    Each crate entry has name, version, sha256, and download URL.

    Args:
        lockfile_path: Path to MODULE.bazel.lock file

    Returns:
        Dict mapping canonical repository names to crate metadata
    """
    with open(lockfile_path, encoding="utf-8") as f:
        lock_data = json.load(f)

    crates = {}
    extensions = lock_data.get("moduleExtensions", {})

    # Find the crate_universe extension (key contains "crate_universe" or "crate")
    crate_ext = None
    for ext_key, ext_val in extensions.items():
        if "crate" in ext_key.lower():
            crate_ext = ext_val
            break

    if not crate_ext:
        print(
            "  WARNING: No crate extension found in MODULE.bazel.lock", file=sys.stderr
        )
        return crates

    # Get generatedRepoSpecs from 'general' (or the first available key)
    general = crate_ext.get("general", {})
    specs = general.get("generatedRepoSpecs", {})

    for repo_name, spec in specs.items():
        # Crate repositories use <hub>__<name>-<version>; skip the hub itself.
        if "__" not in repo_name:
            continue

        crate_part = repo_name.split("__", 1)[1]

        # Parse name-version (e.g., "serde-1.0.228", "iceoryx2-qnx8-0.7.0")
        m = re.match(r"^(.+?)-(\d+\.\d+\.\d+.*)$", crate_part)
        if not m:
            continue

        name = m.group(1)
        version = m.group(2)
        attrs = spec.get("attributes", {})
        sha256 = attrs.get("sha256", "")
        archive_prefix = attrs.get("strip_prefix", "")
        exact_version = archive_prefix.removeprefix(name + "-")
        version_from_repository = True
        if (
            archive_prefix.startswith(name + "-")
            and exact_version.replace("+", "-") == version
        ):
            version = exact_version
            version_from_repository = False

        repository = (
            ext_key.split("//")[0].lstrip("@")
            + "+"
            + ext_key.rsplit("%", 1)[-1]
            + "+"
            + repo_name
        )
        crates[repository] = {
            "name": name,
            "version": version,
            "version_from_repository": version_from_repository,
            "checksum": sha256,
            "source": (
                "registry+https://github.com/rust-lang/crates.io-index"
                if _is_cratesio_archive(attrs, name, version)
                else "module-bazel-lock"
            ),
            "repository": repository,
        }

    return crates


def _is_cratesio_archive(attrs: dict[str, Any], name: str, version: str) -> bool:
    """Only permit API fallback for a matching, unpatched crates.io archive."""
    if any(
        attrs.get(k)
        for k in ("remote", "patches", "remote_patches", "patch_cmds", "patch_cmds_win")
    ):
        return False
    paths = {
        ("static.crates.io", f"/crates/{name}/{version}/download"),
        ("static.crates.io", f"/crates/{name}/{name}-{version}.crate"),
        ("crates.io", f"/api/v1/crates/{name}/{version}/download"),
    }
    urls = attrs.get("urls", []) or [attrs.get("url", "")]
    return bool(urls) and all(
        (parsed.scheme == "https" and (parsed.netloc, parsed.path) in paths)
        for parsed in map(urllib.parse.urlsplit, urls)
    )


def select_build_crates(
    crates: dict[str, dict[str, Any]],
    deps_path: str,
    cargo_packages: list[dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Associate manifests with the selected Bazel repositories, not cache names."""
    with open(deps_path, encoding="utf-8") as f:
        deps = json.load(f)
    repositories = set(deps["external_repos"])
    for edge in deps.get("external_dep_edges", []):
        if "::" in edge:
            destination = edge.split("::", 1)[1].rstrip("+")
            if destination:
                repositories.add(destination)
    selected = {}
    for repo in sorted(repositories):
        if not any(
            marker in repo
            for marker in ("crate_index__", "crates_io__", "_crates__", "crate+")
        ):
            continue
        crate_part = repo.rsplit("+", 1)[-1].split("__", 1)[-1]
        match = re.fullmatch(r"(.+?)-(\d+\.\d+\.\d+.*)", crate_part)
        if not match:
            continue
        name, version = match.groups()
        locked = crates.get(repo, {})
        # A name/version match alone does not prove this is the same source.
        info = locked if locked.get("repository") == repo else {}
        if not info and cargo_packages is not None:
            # In Cargo.lock-only builds, the supplied lockfile describes the source.
            matches = [
                p
                for p in cargo_packages
                if p["name"] == name and p["version"].replace("+", "-") == version
            ]
            if len(matches) == 1:
                info = {**matches[0], "version_from_repository": False}
        selected["repo:" + repo] = {
            **info,
            "name": name,
            "version": info.get("version", version),
            "version_from_repository": info.get("version_from_repository", True),
            "checksum": info.get("checksum", ""),
            "source": info.get("source", "unknown"),
            "repository": repo,
            "manifest": deps.get("crate_manifests", {}).get(repo),
        }
    return selected


def read_manifest_license(info: dict[str, Any]) -> tuple[str, str]:
    """Return a direct license expression or the reason it could not be read."""
    path = info.get("manifest")
    if not path:
        return "", "Cargo.toml unavailable"
    try:
        with open(path, "rb") as f:
            package = tomllib.load(f).get("package", {})
    except (OSError, ValueError) as exc:
        return "", f"Cannot read Cargo.toml: {exc}"
    name, version = package.get("name"), package.get("version")
    if (
        info.get("version_from_repository")
        and isinstance(version, str)
        and version.replace("+", "-") == info["version"]
    ):
        info["version"] = version
    if name != info["name"] or (
        version != info["version"] and version != {"workspace": True}
    ):
        raise ValueError(
            f"Manifest identity mismatch for {info['repository']}: "
            f"expected {info['name']}@{info['version']}, found {name}@{version}"
        )
    if version == {"workspace": True}:
        return "", "Workspace version inheritance is not supported"
    license_expr = package.get("license")
    if isinstance(license_expr, str) and license_expr.strip():
        return _normalize_license_expression(license_expr.strip()), ""
    if license_expr == {"workspace": True}:
        return "", "Workspace license inheritance is not supported"
    if package.get("license-file"):
        return "", "license-file processing is not supported"
    return "", "Cargo.toml has no direct license expression"


def generate_synthetic_cargo_lock(
    crates: dict[str, dict[str, Any]], output_path: str
) -> None:
    """Generate a minimal synthetic Cargo.lock from parsed crate data.

    The dash-license-scan parser splits on '[[package]]' blocks and extracts
    name, version, and source fields. Source must contain 'crates' if present.

    Args:
        crates: Dict mapping name@version to {name, version, checksum, source}
        output_path: Path to write the synthetic Cargo.lock
    """
    lines = ["version = 4", ""]
    for _name, info in sorted(crates.items()):
        lines.append("[[package]]")
        lines.append(f'name = "{info["name"]}"')
        lines.append(f'version = "{info["version"]}"')
        lines.append('source = "registry+https://github.com/rust-lang/crates.io-index"')
        lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def _find_uvx() -> str:
    """Locate the uvx binary, checking PATH and common install locations."""
    found = shutil.which("uvx")
    if found:
        return found

    # Standard uv install location (works inside Bazel sandbox where PATH is minimal)
    home = os.environ.get("HOME", os.path.expanduser("~"))
    candidate = os.path.join(home, ".local", "bin", "uvx")
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate

    return "uvx"  # fall back, will raise FileNotFoundError in subprocess


def run_dash_license_scan(
    cargo_lock_path: str, summary_output_path: str, verbose: bool = False
) -> None:
    """Invoke dash-license-scan via uvx and write summary to file.

    Args:
        cargo_lock_path: Path to (real or synthetic) Cargo.lock
        summary_output_path: Path to write the dash-licenses summary CSV

    Raises:
        SystemExit: If uvx/dash-license-scan is not found or fatally crashes
    """
    uvx = _find_uvx()
    cmd = [
        uvx,
        "--from",
        "dash-license-scan@git+https://github.com/eclipse-score/dash-license-scan",
        "dash-license-scan",
    ]
    if verbose:
        cmd.append("-v")
    cmd.extend(["--summary", summary_output_path, cargo_lock_path])
    print(f"Running: {' '.join(cmd)}")

    # Redirect uv's cache and tool directories to writable temp locations.
    # Inside Bazel sandbox, ~/.cache and ~/.local/share are read-only.
    env = os.environ.copy()
    uv_tmp = os.path.join(tempfile.gettempdir(), "uv_sbom")
    if "UV_CACHE_DIR" not in env:
        env["UV_CACHE_DIR"] = os.path.join(uv_tmp, "cache")
    if "UV_TOOL_DIR" not in env:
        env["UV_TOOL_DIR"] = os.path.join(uv_tmp, "tools")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            env=env,
        )
    except FileNotFoundError:
        print(
            "ERROR: 'uvx' not found on PATH or ~/.local/bin/. Install uv: https://docs.astral.sh/uv/",
            file=sys.stderr,
        )
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("ERROR: dash-license-scan timed out after 600 seconds", file=sys.stderr)
        sys.exit(1)

    # dash-license-scan exits with returncode = number of restricted items.
    # This is normal behavior, not an error. Only signal kills are fatal.
    if result.returncode < 0:
        print(
            f"ERROR: dash-license-scan killed by signal {-result.returncode}",
            file=sys.stderr,
        )
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        sys.exit(1)

    if result.stderr:
        # Print dash-license-scan's own output (INFO lines from the JAR)
        for line in result.stderr.splitlines():
            print(f"  {line}")

    if not os.path.exists(summary_output_path):
        print(
            f"ERROR: dash-license-scan did not produce summary file: {summary_output_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    if result.returncode > 0:
        print(f"  NOTE: {result.returncode} crate(s) have 'restricted' license status")


def parse_dash_summary(summary_path: str) -> dict[str, str]:
    """Parse the dash-licenses summary CSV file into a license lookup dict.

    Each line has format:
        crate/cratesio/-/<name>/<version>, <license_expr>, <status>, <source>

    Args:
        summary_path: Path to the dash-licenses summary file

    Returns:
        Dict mapping name@version to SPDX license expression string
    """
    licenses: dict[str, str] = {}
    with open(summary_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 4:
                continue

            content_id = parts[0]
            license_expr = parts[1].strip()

            # Extract crate name from content_id: "crate/cratesio/-/<name>/<version>"
            id_parts = content_id.split("/")
            if len(id_parts) >= 5 and id_parts[0] == "crate":
                crate_name = id_parts[3]
                if license_expr:
                    licenses[f"{crate_name}@{id_parts[4]}"] = license_expr

    return licenses


def _extract_supplier(repository_url: str) -> str:
    """Extract supplier (GitHub org/user) from a repository URL.

    Examples:
        https://github.com/serde-rs/serde -> serde-rs
        https://github.com/eclipse-iceoryx/iceoryx2 -> eclipse-iceoryx
    """
    if not repository_url:
        return ""
    m = re.match(r"https?://github\.com/([^/]+)/", repository_url)
    return m.group(1) if m else ""


def _normalize_license_expression(license_expr: str) -> str:
    """Normalize common crates.io license separators to SPDX-style operators."""
    if not license_expr:
        return ""
    # crates.io commonly uses "/" as OR.
    return " OR ".join(part.strip() for part in license_expr.split("/") if part.strip())


_request_lock = threading.Lock()
_last_request = 0.0


def _cratesio_get(url: str) -> dict[str, Any]:
    """Limit API requests to one per second and retry transient failures."""
    global _last_request
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "score-sbom-tool (https://github.com/eclipse-score/sbom-tool)"
        },
    )
    for attempt in range(3):
        with _request_lock:
            delay = 1.0 - (time.monotonic() - _last_request)
            if delay > 0:
                time.sleep(delay)
            _last_request = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                if not isinstance(data, dict):
                    raise ValueError("API response must be a JSON object")
                return data
        except (OSError, http.client.HTTPException) as exc:
            if isinstance(exc, urllib.error.HTTPError):
                if exc.code != 429 and not 500 <= exc.code < 600:
                    raise
            if attempt == 2:
                if isinstance(exc, http.client.HTTPException):
                    raise urllib.error.URLError(exc) from exc
                raise
            time.sleep(2**attempt)
    raise AssertionError("Unreachable")


def _fetch_one_crate_meta(
    name: str, version: str, fetch_license: bool = True
) -> tuple[str, dict[str, str]]:
    """Fetch an exact-version license when needed; retain existing description lookup."""
    meta = {"license": "", "description": "", "supplier": ""}
    if fetch_license:
        url = f"https://crates.io/api/v1/crates/{name}/{version}"
        try:
            version_data = _cratesio_get(url).get("version", {})
            if not isinstance(version_data, dict):
                raise ValueError("API response has invalid version metadata")
            if (
                version_data.get("crate", name) != name
                or version_data.get("num", version) != version
            ):
                raise ValueError("API response identifies a different crate or version")
            license_expr = version_data.get("license")
            if isinstance(license_expr, str) and license_expr.strip():
                meta["license"] = _normalize_license_expression(license_expr.strip())
                meta["license_source"] = url
            else:
                meta["license_error"] = "API response has no license expression"
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            meta["license_error"] = f"API request failed ({url}): {exc}"

    candidates = [name]
    if name.endswith("-qnx8"):
        candidates.append(name[: -len("-qnx8")])
    for candidate in candidates:
        try:
            data = _cratesio_get(f"https://crates.io/api/v1/crates/{candidate}")
            crate = data.get("crate", {})
            meta["description"] = (crate.get("description") or "").strip()
            meta["supplier"] = _extract_supplier(crate.get("repository", ""))
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            print(
                f"WARNING: Metadata request failed for {candidate}: {exc}",
                file=sys.stderr,
            )
        if meta["description"] or meta["supplier"] or meta["license"]:
            break
    return name, meta


def fetch_crate_metadata_from_cratesio(
    crate_versions: list[tuple[str, str]],
    license_lookups: set[tuple[str, str]] | None = None,
) -> dict[str, dict[str, str]]:
    """Fetch metadata (description, supplier, license) from crates.io API (parallel).

    Args:
        crate_versions: List of (crate name, locked version) pairs

    Returns:
        Dict mapping name@version to {description, supplier, license}
    """
    total = len(crate_versions)
    print(f"Fetching metadata from crates.io for {total} crates...")

    metadata: dict[str, dict[str, str]] = {}
    done = 0
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {
            pool.submit(
                _fetch_one_crate_meta,
                name,
                version,
                license_lookups is None or (name, version) in license_lookups,
            ): f"{name}@{version}"
            for name, version in crate_versions
        }
        for future in as_completed(futures):
            _name, meta = future.result()
            if meta:
                metadata[futures[future]] = meta
            done += 1
            if done % 50 == 0:
                print(f"  ... {done}/{total} crates queried")

    with_desc = sum(1 for m in metadata.values() if m.get("description"))
    with_supplier = sum(1 for m in metadata.values() if m.get("supplier"))
    with_license = sum(1 for m in metadata.values() if m.get("license"))
    print(
        f"Retrieved from crates.io: {with_desc} descriptions, "
        f"{with_supplier} suppliers, {with_license} licenses"
    )
    return metadata


def generate_cache(
    cargo_lock_path: str | None = None,
    module_lock_paths: list[str] | None = None,
    use_dash_license_scan: bool = False,
    verbose: bool = False,
    deps_path: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Collect direct manifest licenses, with an exact-version registry fallback.

    1. Parse Cargo.lock and/or MODULE.bazel.lock files for crate names, versions, checksums
    2. Read available crate manifests, optionally use dash-license-scan
    3. Fetch descriptions, suppliers, and license fallback from crates.io (parallel)
    4. Combine version/checksum from lockfile with metadata

    Args:
        cargo_lock_path: Optional path to Cargo.lock file
        module_lock_paths: Optional list of paths to MODULE.bazel.lock files
        deps_path: Bazel dependency data with repository-to-manifest paths

    Returns:
        Metadata keyed by Bazel repository, or name@version for standalone lockfiles
    """
    crates: dict[str, dict[str, Any]] = {}
    repositories: dict[str, dict[str, Any]] = {}

    if cargo_lock_path:
        print(f"Parsing {cargo_lock_path}...")
        crates = parse_cargo_lock(cargo_lock_path)
        print(f"Found {len(crates)} crates from Cargo.lock")

    # Merge crates from MODULE.bazel.lock files
    for module_lock_path in module_lock_paths or []:
        print(f"Parsing {module_lock_path}...")
        module_crates = parse_module_bazel_lock(module_lock_path)
        for info in module_crates.values():
            repo = info["repository"]
            if repo in repositories and repositories[repo] != info:
                raise ValueError(f"Conflicting crate sources for {repo}")
            repositories[repo] = info
        added = 0
        for info in module_crates.values():
            key = f"{info['name']}@{info['version']}"
            if key not in crates:
                crates[key] = info
                added += 1
        print(f"Found {len(module_crates)} crates in {module_lock_path} ({added} new)")

    if deps_path:
        cargo_packages = None
        if cargo_lock_path and not module_lock_paths:
            with open(cargo_lock_path, "rb") as f:
                cargo_packages = tomllib.load(f).get("package", [])
        crates = select_build_crates(repositories, deps_path, cargo_packages)

    if not crates:
        print("No selected crates found.")
        return {}

    local_licenses = {key: read_manifest_license(info) for key, info in crates.items()}
    registry_crates = {
        key: info
        for key, info in crates.items()
        if info["source"]
        in (
            "registry+https://github.com/rust-lang/crates.io-index",
            "sparse+https://index.crates.io/",
        )
    }
    license_map: dict[str, str] = {}
    if use_dash_license_scan:
        # Generate synthetic Cargo.lock containing only crates.io crates.
        # This avoids dash-license-scan's ValueError on non-crates.io sources
        # (git dependencies, path dependencies) that may be in a real Cargo.lock.
        temp_dir = tempfile.mkdtemp(prefix="sbom_dash_")
        synthetic_path = os.path.join(temp_dir, "Cargo.lock")
        generate_synthetic_cargo_lock(registry_crates, synthetic_path)
        print(f"Generated synthetic Cargo.lock with {len(registry_crates)} crates")

        summary_path = os.path.join(temp_dir, "dash_summary.txt")

        try:
            print("Fetching license data via dash-license-scan...")
            run_dash_license_scan(synthetic_path, summary_path, verbose=verbose)
            license_map = parse_dash_summary(summary_path)
            print(f"Retrieved licenses for {len(license_map)} crates")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    # Description/supplier collection still uses the API. License requests are fallback only.
    license_lookups = {
        (info["name"], info["version"])
        for key, info in registry_crates.items()
        if not local_licenses[key][0]
        and f"{info['name']}@{info['version']}" not in license_map
    }
    cratesio_meta = fetch_crate_metadata_from_cratesio(
        sorted({(info["name"], info["version"]) for info in crates.values()}),
        license_lookups=license_lookups,
    )

    # Build final cache
    cache: dict[str, dict[str, Any]] = {}
    for key, info in crates.items():
        identity = f"{info['name']}@{info['version']}"
        meta = cratesio_meta.get(identity, {})
        license_expr, reason = local_licenses[key]
        license_source = info.get("manifest", "") if license_expr else ""
        if not license_expr and key in registry_crates:
            license_expr = license_map.get(identity, meta.get("license", ""))
            license_source = (
                "dash-license-scan"
                if identity in license_map
                else meta.get("license_source", "")
            )
            reason += "; " + meta.get(
                "license_error", "API response has no license expression"
            )
        elif not license_expr:
            reason += "; API license fallback requires a confirmed crates.io source"
        cache[key] = {
            "name": info["name"],
            "version": info["version"],
            "checksum": info["checksum"],
            "purl": f"pkg:cargo/{info['name']}@{info['version']}",
            "license": license_expr,
            "license_source": license_source,
            "description": meta.get("description", ""),
            "supplier": meta.get("supplier", ""),
        }
        if info.get("repository"):
            cache[key]["bazel_repository"] = info["repository"]
        if not license_expr:
            cache[key]["license_error"] = reason
            print(f"WARNING: License unresolved for {key}: {reason}", file=sys.stderr)

    return cache


def main():
    parser = argparse.ArgumentParser(
        description="Generate crates metadata cache for SBOM generation"
    )
    parser.add_argument(
        "output",
        nargs="?",
        default="crates_metadata.json",
        help="Output JSON file (default: crates_metadata.json)",
    )
    parser.add_argument("--cargo-lock", help="Path to Cargo.lock file")
    parser.add_argument(
        "--deps-json", help="Bazel dependency data with crate manifest paths"
    )
    parser.add_argument(
        "--module-lock",
        action="append",
        default=[],
        help="Path to MODULE.bazel.lock for additional crates (can be repeated)",
    )
    parser.add_argument(
        "--merge", help="Merge with existing cache file instead of overwriting"
    )
    parser.add_argument(
        "--use-dash-license-scan",
        action="store_true",
        help="Use dash-license-scan for Rust licenses (requires uvx and Java)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    args = parser.parse_args()

    if not args.cargo_lock and not args.module_lock and not args.deps_json:
        parser.error(
            "At least one of --cargo-lock, --module-lock or --deps-json is required"
        )

    # Generate new cache
    cache = generate_cache(
        cargo_lock_path=args.cargo_lock,
        module_lock_paths=args.module_lock,
        use_dash_license_scan=args.use_dash_license_scan,
        verbose=args.verbose,
        deps_path=args.deps_json,
    )

    # Merge with existing cache if requested
    if args.merge and Path(args.merge).exists():
        print(f"\nMerging with existing cache: {args.merge}")
        with open(args.merge) as f:
            existing = json.load(f)

        # Prefer new data, but keep entries not in current lockfiles
        merged = existing.copy()
        merged.update(cache)
        cache = merged
        print(f"Merged cache now contains {len(cache)} entries")

    if not cache:
        print("\nNo crates to write.")
        with open(args.output, "w") as f:
            json.dump({}, f)
        return 0

    # Write cache
    print(f"\nWriting cache to {args.output}...")
    with open(args.output, "w") as f:
        json.dump(cache, f, indent=2, sort_keys=True)

    # Print statistics
    total = len(cache)
    with_license = sum(1 for c in cache.values() if c.get("license"))
    with_checksum = sum(1 for c in cache.values() if c.get("checksum"))
    with_desc = sum(1 for c in cache.values() if c.get("description"))
    with_supplier = sum(1 for c in cache.values() if c.get("supplier"))

    print(f"\n✓ Cache generated successfully!")
    print(f"  Total crates: {total}")
    print(f"  With licenses: {with_license} ({with_license / total * 100:.1f}%)")
    print(f"  With checksums: {with_checksum} ({with_checksum / total * 100:.1f}%)")
    print(f"  With descriptions: {with_desc} ({with_desc / total * 100:.1f}%)")
    print(f"  With suppliers: {with_supplier} ({with_supplier / total * 100:.1f}%)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
