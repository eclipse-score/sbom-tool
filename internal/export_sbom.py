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

"""Copy the configured SBOM reports from Bazel runfiles to their destination."""

import json
import os
import shutil
from pathlib import Path
from tempfile import TemporaryDirectory

from python.runfiles import runfiles


def main() -> None:
    destination = (
        Path(os.environ["BUILD_WORKSPACE_DIRECTORY"]) / os.environ["SBOM_OUTPUT_DIR"]
    )
    destination.mkdir(parents=True, exist_ok=True)
    files = runfiles.Create()
    with TemporaryDirectory(dir=destination) as staging:
        for report in json.loads(os.environ["SBOM_REPORTS"]):
            source = Path(files.Rlocation(report))
            output = destination / Path(report).name
            if not output.exists() or not source.samefile(output):
                staged = Path(staging) / output.name
                shutil.copyfile(source, staged)
                staged.replace(output)
            print(output)


if __name__ == "__main__":
    main()
