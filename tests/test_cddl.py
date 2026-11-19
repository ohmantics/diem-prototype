"""An independent check of the CDDL reader: the real cddl tool, over every example.   # draft: #profiles

Each example record is encoded with its names left as text and checked with
the cddl command-line tool, if it is installed.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from diem import emblem
from examples.records import ALL, logistics

PROFILES = Path(__file__).resolve().parent.parent / "profiles"
pytestmark = pytest.mark.skipif(
    shutil.which("cddl") is None, reason="the cddl tool is not installed"
)


def schema(rule, directory):
    text = "".join(path.read_text() for path in sorted(PROFILES.glob("*.cddl")))
    path = directory / f"{rule}.cddl"
    path.write_text(f"root = {rule}\n{text}")
    return path


def validate(rule, data, directory):
    data_file = directory / "record.cbor"
    data_file.write_bytes(data)
    run = subprocess.run(
        [
            "cddl",
            "validate",
            "--cddl",
            str(schema(rule, directory)),
            "--cbor",
            str(data_file),
        ],
        capture_output=True,
        text=True,
    )
    return run.stdout + run.stderr


@pytest.mark.parametrize("example", ALL, ids=lambda example: example.owner)
def test_example_conforms_to_its_cddl(example, tmp_path):
    rule = (
        f"{example.plaintext}-plaintext"
        if example.plaintext
        else f"{example.profile_name}-emblem"
    )
    data = emblem.to_cbor(example.record, example.key_spaces, text_names=True)
    report = validate(rule, data, tmp_path)
    # The tool exits with success even when validation fails, so read its report.
    assert "is successful" in report and "[ERROR]" not in report, report


def test_a_record_that_breaks_a_rule_is_refused(tmp_path):
    record = {**logistics.PALLET, "country": "vn"}
    report = validate(
        "ispm15-emblem", emblem.to_cbor(record, text_names=True), tmp_path
    )
    assert "is successful" not in report
