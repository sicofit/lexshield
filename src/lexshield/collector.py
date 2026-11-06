"""Runs the read-only PowerShell collector and returns its facts."""

from __future__ import annotations

import json
import os
import subprocess
from importlib import resources

# -ExecutionPolicy Bypass applies to this one process only; it changes no system setting.
POWERSHELL = [
    "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
]


class CollectorError(RuntimeError):
    pass


def collect(timeout: int = 180) -> dict:
    if os.name != "nt":
        raise CollectorError(
            "Die Erhebung läuft nur unter Windows. Gespeicherte Daten prüfen: lexshield scan --facts DATEI"
        )
    script = resources.files("lexshield").joinpath("collect.ps1")
    with resources.as_file(script) as path:
        try:
            proc = subprocess.run([*POWERSHELL, str(path)], capture_output=True, timeout=timeout, check=False)
        except FileNotFoundError as exc:
            raise CollectorError("powershell.exe nicht gefunden") from exc
        except subprocess.TimeoutExpired as exc:
            raise CollectorError(f"Erhebung nach {timeout} s abgebrochen") from exc
    output = proc.stdout.decode("utf-8-sig", errors="replace").strip()
    if proc.returncode != 0 or not output:
        error = proc.stderr.decode("utf-8", errors="replace").strip()
        raise CollectorError(f"PowerShell-Fehler (Code {proc.returncode}): {error[:500]}")
    try:
        facts = json.loads(output)
    except json.JSONDecodeError as exc:
        raise CollectorError("Die Ausgabe der Erhebung ist kein gültiges JSON") from exc
    if not isinstance(facts, dict) or facts.get("schema") != 1:
        raise CollectorError("Unbekanntes Format der Erhebung")
    return facts
