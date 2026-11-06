"""Reading and cleaning snapshots."""

from datetime import date

import pytest

from lexshield.facts import FactsError, normalize, read_facts, reference_date


def test_reads_utf16_utf8_bom_and_ansi(tmp_path):
    for encoding in ("utf-16", "utf-16-be", "utf-8-sig", "utf-8", "cp1252"):
        path = tmp_path / f"{encoding}.json"
        path.write_bytes(('{"host": {"name": "Zürich"}}').encode(encoding))
        if encoding == "utf-16-be":  # Python writes no BOM for an explicit byte order
            path.write_bytes(b"\xfe\xff" + path.read_bytes())
        assert read_facts(str(path))["host"]["name"] == "Zürich", encoding


@pytest.mark.parametrize("content", ["", "{", "[]", "null", "42", '"x"', "[" * 100_000])
def test_unusable_files_raise_facts_error(tmp_path, content):
    path = tmp_path / "bad.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(FactsError):
        read_facts(str(path))


def test_missing_file_raises_facts_error(tmp_path):
    with pytest.raises(FactsError):
        read_facts(str(tmp_path / "fehlt.json"))


def test_normalize_drops_sections_in_the_wrong_format_and_strips_control_characters():
    facts = normalize({"host": {"name": "PC\x1b[2K\n## x"}, "os": "Windows", "lock": [], "collector_errors": "x"})
    assert facts["host"]["name"] == "PC [2K ## x"  # ESC and the line break each become a space
    assert facts["os"] is None and facts["lock"] is None
    assert facts["collector_errors"] == ["os: unerwartetes Format, nicht ausgewertet",
                                         "lock: unerwartetes Format, nicht ausgewertet"]


def test_normalize_survives_any_root_and_deep_nesting():
    assert normalize([1, 2])["collector_errors"] == ["Erhebung ist kein JSON-Objekt"]
    deep: dict = {}
    current = deep
    for _ in range(500):
        current["x"] = {}
        current = current["x"]
    assert normalize({"office": deep})["office"] is not None


@pytest.mark.parametrize(
    ("stamp", "expected", "note"),
    [
        ("2026-11-05T09:12:00+01:00", date(2026, 11, 5), None),
        (None, date(2026, 11, 6), "Erhebungsdatum fehlt, Stichtag heute"),
        ("05.11.2026 09:12", date(2026, 11, 6), "Erhebungsdatum unlesbar, Stichtag heute"),
        ("2099-01-01T00:00:00", date(2099, 1, 1), "Erhebungsdatum liegt in der Zukunft"),
    ],
)
def test_reference_date_says_when_it_is_not_the_collection_date(stamp, expected, note):
    assert reference_date({"collected_at": stamp}, today=date(2026, 11, 6)) == (expected, note)
