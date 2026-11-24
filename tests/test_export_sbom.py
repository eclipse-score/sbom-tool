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

"""Regression tests for replacing an exported SBOM."""

import json
from unittest.mock import patch

import pytest

from internal import export_sbom


@pytest.fixture
def reports(tmp_path, monkeypatch):
    runfiles_dir = tmp_path / "runfiles"
    report_key = "_sbom_reports/sbom.spdx.json"
    source = runfiles_dir / report_key
    source.parent.mkdir(parents=True)
    source.write_bytes(b'{"version": 2}')

    output = tmp_path / "reports" / source.name
    output.parent.mkdir()
    output.write_bytes(b'{"version": 1}')

    monkeypatch.delenv("RUNFILES_MANIFEST_FILE", raising=False)
    monkeypatch.setenv("RUNFILES_DIR", str(runfiles_dir))
    monkeypatch.setenv("BUILD_WORKSPACE_DIRECTORY", str(tmp_path))
    monkeypatch.setenv("SBOM_OUTPUT_DIR", "reports")
    monkeypatch.setenv("SBOM_REPORTS", json.dumps([report_key]))
    return source, output


def test_replaces_existing_report(reports):
    source, output = reports
    export_sbom.main()
    assert output.read_bytes() == source.read_bytes()


def test_partial_copy_preserves_previous_report(reports, monkeypatch):
    _, output = reports
    previous = output.read_bytes()

    def interrupted_copy(source, destination):
        destination.write_bytes(b"partial")
        raise OSError("copy interrupted")

    monkeypatch.setattr(export_sbom.shutil, "copyfile", interrupted_copy)
    with pytest.raises(OSError, match="copy interrupted"):
        export_sbom.main()

    assert output.read_bytes() == previous
    assert list(output.parent.iterdir()) == [output]


def test_skips_copy_when_destination_is_source(reports, monkeypatch):
    source, _ = reports
    monkeypatch.setenv("SBOM_OUTPUT_DIR", str(source.parent))
    with patch.object(export_sbom.shutil, "copyfile") as copyfile:
        export_sbom.main()
    copyfile.assert_not_called()
