"""Each walkthrough runs in local mode, and prints for people: no hex.   # draft: #examples"""

import importlib
import re
import sys

import pytest

NAMES = ["pouch", "hospital", "pallet", "peacekeepers", "diverted_flight"]


@pytest.mark.parametrize("name", NAMES)
def test_the_walkthrough_runs_and_prints_no_hex(name, capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["python"])
    importlib.import_module(f"examples.{name}").main()
    shown = capsys.readouterr().out
    assert re.search(r"\bVALID:", shown)
    assert not re.search(r"[0-9a-f]{16}", shown.replace("h'...'", ""))
