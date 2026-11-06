"""Runs the real collector. Opt-in: set LEXSHIELD_LIVE=1 on Windows."""

import os

import pytest

from lexshield.collector import collect
from lexshield.engine import evaluate, load_rules

pytestmark = pytest.mark.skipif(
    os.name != "nt" or os.environ.get("LEXSHIELD_LIVE") != "1",
    reason="live test: set LEXSHIELD_LIVE=1 on Windows",
)


def test_collector_on_this_machine():
    facts = collect()
    assert facts["schema"] == 1
    assert isinstance(facts["os"]["build"], int)
    for folder in (facts.get("local_docs") or {}).values():
        if folder is not None:
            assert set(folder) == {"documents", "older_than_30_days"}
            assert all(isinstance(value, int) for value in folder.values())
    report = evaluate(facts)
    assert len(report.findings) == len(load_rules())
    assert not any(f.detail.startswith("Prüfung fehlgeschlagen") for f in report.findings)
