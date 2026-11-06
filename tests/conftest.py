import json
from datetime import date
from pathlib import Path

import pytest

from lexshield.checks import Context
from lexshield.engine import load_lifecycle

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def load_example(name: str) -> dict:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


@pytest.fixture
def risky() -> dict:
    return load_example("kanzlei-riskant.json")


@pytest.fixture
def solid() -> dict:
    return load_example("kanzlei-solide.json")


@pytest.fixture
def ctx() -> Context:
    return Context(ref_date=date(2026, 11, 5), lifecycle=load_lifecycle())
