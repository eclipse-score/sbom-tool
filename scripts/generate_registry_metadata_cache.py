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

"""Download and check source.json files listed in the lockfiles."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
import urllib.error
import urllib.request

from internal.generator.registry_metadata import (
    archive_metadata,
    registry_source_hashes,
)


def generate_cache(lockfiles: list[str]) -> dict[str, str]:
    """Download each file, check its hash, and save its text under its URL."""
    sources = registry_source_hashes(lockfiles)

    def fetch(url: str) -> tuple[str, str]:
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                source_text = response.read().decode("utf-8")
            archive_metadata(source_text, sources[url])
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise ValueError(f"Cannot verify registry metadata {url}: {exc}") from exc
        return url, source_text

    with ThreadPoolExecutor(max_workers=8) as pool:
        return dict(pool.map(fetch, sorted(sources)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", help="Output cache of verified source.json text")
    parser.add_argument("--module-lock", action="append", required=True)
    args = parser.parse_args()
    try:
        cache = generate_cache(args.module_lock)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    Path(args.output).write_text(
        json.dumps(cache, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
