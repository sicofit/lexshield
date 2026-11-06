"""Reading a facts snapshot and cleaning it before any check sees it."""

from __future__ import annotations

import json
import re
from datetime import date, datetime
from pathlib import Path

# Sections the collector writes as objects. Anything else in their place counts as missing.
SECTIONS = (
    "host", "os", "antivirus", "defender", "firewall", "bitlocker", "updates", "accounts",
    "uac", "smb1", "rdp", "lock", "office", "removable", "network", "local_docs",
)
# Control characters, ESC included: in a terminal they move the cursor, in Markdown
# a line break inside a name starts a new heading.
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
MAX_DEPTH = 12  # the collector writes four levels; deeper nesting is dropped


class FactsError(Exception):
    """A snapshot that cannot be read at all."""


def decode(raw: bytes) -> str:
    """UTF-8 as the collector writes it; UTF-16 as Windows PowerShell's ">" writes it; else ANSI."""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def read_facts(path: str) -> dict:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise FactsError(f"Erhebung nicht lesbar: {exc}") from exc
    try:
        data = json.loads(decode(raw))
    except UnicodeDecodeError as exc:
        raise FactsError("Erhebung nicht lesbar: unbekannte Zeichenkodierung") from exc
    except (ValueError, RecursionError) as exc:  # bad JSON, an integer over 4300 digits, deep nesting
        raise FactsError(f"Erhebung ist kein gültiges JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise FactsError("Erhebung ist kein JSON-Objekt. Erwartet wird eine Datei von «lexshield collect».")
    return data


def clean(value: object, depth: int = 0) -> object:
    if depth > MAX_DEPTH:
        return None
    if isinstance(value, str):
        return CONTROL.sub(" ", value)
    if isinstance(value, list):
        return [clean(item, depth + 1) for item in value]
    if isinstance(value, dict):
        return {CONTROL.sub(" ", str(key)): clean(item, depth + 1) for key, item in value.items()}
    return value


def normalize(facts: object) -> dict:
    """A copy every check can rely on: each section is an object or absent, no text carries control characters.

    A section in an unexpected format is dropped and noted in collector_errors, so the
    report says why its checks could not run.
    """
    if not isinstance(facts, dict):
        return {"collector_errors": ["Erhebung ist kein JSON-Objekt"]}
    cleaned = clean(facts)
    errors = cleaned.get("collector_errors")
    errors = [str(error) for error in errors] if isinstance(errors, list) else []
    for key in SECTIONS:
        if cleaned.get(key) is not None and not isinstance(cleaned[key], dict):
            errors.append(f"{key}: unerwartetes Format, nicht ausgewertet")
            cleaned[key] = None
    cleaned["collector_errors"] = errors
    return cleaned


def reference_date(facts: dict, today: date | None = None) -> tuple[date, str | None]:
    """The date a snapshot is evaluated against, and a note when it is not the collection date.

    A saved snapshot is evaluated against its collection date, so it always gives the same report.
    """
    today = today or date.today()
    stamp = facts.get("collected_at")
    if not stamp:
        return today, "Erhebungsdatum fehlt, Stichtag heute"
    try:
        collected = datetime.fromisoformat(str(stamp)).date()
    except ValueError:
        return today, "Erhebungsdatum unlesbar, Stichtag heute"
    if collected > today:
        return collected, "Erhebungsdatum liegt in der Zukunft"
    return collected, None
