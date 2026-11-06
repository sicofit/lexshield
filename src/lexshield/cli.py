"""Command line interface."""

from __future__ import annotations

import argparse
import codecs
import io
import json
import os
import shutil
import sys
from pathlib import Path

from . import __version__
from .collector import CollectorError, collect
from .engine import SEVERITIES, evaluate, find_rule, load_law, load_profiles, load_rules
from .facts import FactsError, read_facts
from .report import (
    render_explain,
    render_law,
    render_markdown,
    render_profiles,
    render_rules,
    render_terminal,
    report_to_dict,
)


# Characters a code page such as 850 lacks, written so that the text stays readable.
PLAIN = {
    "\N{EN DASH}": "-", "\N{EM DASH}": "-", "\N{RIGHTWARDS ARROW}": "->", "\N{SINGLE RIGHT-POINTING ANGLE QUOTATION MARK}": ">",
    "\N{SINGLE LEFT-POINTING ANGLE QUOTATION MARK}": "<", "\N{HORIZONTAL ELLIPSIS}": "...",
    "\N{LEFT-POINTING DOUBLE ANGLE QUOTATION MARK}": '"', "\N{RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK}": '"',
    "\N{NO-BREAK SPACE}": " ", "\N{NON-BREAKING HYPHEN}": "-",
}


def plain(error: UnicodeEncodeError) -> tuple[str, int]:
    text = error.object[error.start:error.end]
    return "".join(PLAIN.get(char, "?") for char in text), error.end


codecs.register_error("lexshield", plain)


def console_code_page() -> int:
    """The code page of the console this process belongs to, 0 without one."""
    try:
        import ctypes

        return int(ctypes.windll.kernel32.GetConsoleOutputCP())
    except (AttributeError, OSError):
        return 0


def configure_output() -> None:
    """Console output stays Unicode. Output redirected into another program or a file follows
    the console's code page, as Windows' own tools do, so PowerShell and cmd read umlauts right."""
    for stream in (sys.stdout, sys.stderr):
        if not hasattr(stream, "reconfigure"):
            continue
        encoding = None
        try:
            redirected = os.name == "nt" and not stream.isatty() and stream.fileno() >= 0
        except (OSError, ValueError, io.UnsupportedOperation):  # a stand-in stream, as in tests
            redirected = False
        if redirected and not os.environ.get("PYTHONIOENCODING") and not sys.flags.utf8_mode:
            page = console_code_page()
            try:
                encoding = codecs.lookup(f"cp{page}").name if page else None
            except LookupError:
                encoding = None
        stream.reconfigure(encoding=encoding or stream.encoding, errors="lexshield")


def terminal_width() -> int:
    return shutil.get_terminal_size((100, 24)).columns


def color_supported(stream) -> bool:
    if os.environ.get("NO_COLOR") or not stream.isatty():
        return False
    if os.name != "nt":
        return True
    try:  # enable ANSI escape sequences in the classic Windows console
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except (AttributeError, OSError):
        return False


def build_parser(profiles: dict) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lexshield",
        description="Lesende Windows-Sicherheitsprüfung für Anwaltskanzleien in der Schweiz.",
    )
    parser.add_argument("--version", action="version", version=f"lexshield {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="BEFEHL")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true", help="ohne Farben")

    scan = commands.add_parser("scan", parents=[common], help="dieses Gerät prüfen (oder eine gespeicherte Erhebung)")
    scan.add_argument("--profile", choices=list(profiles), default="klein", help="Kanzleiprofil (Standard: klein)")
    scan.add_argument("--facts", metavar="DATEI", help="gespeicherte Erhebung auswerten statt neu zu erheben")
    scan.add_argument("--save-facts", metavar="DATEI", help="Erhebung als JSON speichern")
    scan.add_argument("--json", metavar="DATEI", help="Bericht als JSON speichern")
    scan.add_argument("--md", metavar="DATEI", help="Bericht als Markdown speichern")
    scan.add_argument(
        "--fail-on", choices=[*SEVERITIES, "never"], default="high",
        help="Exit-Code 1 ab dieser Schwere (Standard: high)",
    )
    view = scan.add_mutually_exclusive_group()
    view.add_argument("--brief", action="store_true", help="nur Befunde zeigen")
    view.add_argument("--verbose", action="store_true", help="Risiko und Massnahme auch bei erfüllten Regeln")

    collect_cmd = commands.add_parser("collect", help="nur erheben und als JSON speichern")
    collect_cmd.add_argument("-o", "--output", metavar="DATEI", required=True)

    explain = commands.add_parser("explain", parents=[common], help="einen Punkt mit Rechtsrahmen erklären")
    explain.add_argument("rule_name", metavar="KURZNAME", help="zum Beispiel virenschutz (Liste: lexshield rules)")

    commands.add_parser("law", parents=[common], help="Rechtsrahmen: Pflichten, Normen, wer gebunden ist, offene Fragen")
    commands.add_parser("rules", parents=[common], help="alle Prüfpunkte mit Kurznamen auflisten")
    commands.add_parser("profiles", parents=[common], help="Kanzleiprofile auflisten")
    return parser


def fail(message: str) -> int:
    print(f"lexshield: {message}", file=sys.stderr)
    return 2


def target_problem(path: str | None) -> str | None:
    """Why a file cannot be written there, checked before the audit runs."""
    if not path:
        return None
    target = Path(path)
    if target.is_dir():
        return f"{path} ist ein Ordner, angegeben werden muss ein Dateiname"
    if not target.parent.is_dir():
        return f"Den Ordner {target.parent} gibt es nicht"
    return None


def write_file(path: str, text: str) -> str | None:
    """Write text, or return why it failed."""
    try:
        Path(path).write_text(text, encoding="utf-8")
    except OSError as exc:
        return f"{path} nicht schreibbar: {exc.strerror or exc}"
    return None


def as_json(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def cmd_scan(args: argparse.Namespace, profiles: dict) -> int:
    for path in (args.save_facts, args.json, args.md):
        if problem := target_problem(path):
            return fail(problem)
    if args.facts:
        try:
            facts = read_facts(args.facts)
        except FactsError as exc:
            return fail(str(exc))
    else:
        if sys.stderr.isatty():
            print("LexShield liest die Einstellungen dieses Geräts …", file=sys.stderr)
        try:
            facts = collect()
        except CollectorError as exc:
            return fail(str(exc))
    if args.save_facts and (problem := write_file(args.save_facts, as_json(facts))):
        return fail(problem)

    report = evaluate(facts, args.profile, profiles=profiles)
    mode = "brief" if args.brief else "verbose" if args.verbose else "normal"
    law = load_law()
    print(render_terminal(report, color=use_color(args), width=terminal_width(), mode=mode, law=law))

    if args.json:
        if problem := write_file(args.json, as_json(report_to_dict(report, law))):
            return fail(problem)
        print(f"\nJSON-Bericht: {args.json}", file=sys.stderr)
    if args.md:
        if problem := write_file(args.md, render_markdown(report, law)):
            return fail(problem)
        print(f"\nMarkdown-Bericht: {args.md}", file=sys.stderr)
    if args.fail_on != "never" and report.reaches(args.fail_on):
        return 1
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    if problem := target_problem(args.output):
        return fail(problem)
    try:
        facts = collect()
    except CollectorError as exc:
        return fail(str(exc))
    if problem := write_file(args.output, as_json(facts)):
        return fail(problem)
    print(f"Erhebung gespeichert: {args.output}")
    return 0


def cmd_explain(args: argparse.Namespace, profiles: dict) -> int:
    rules = load_rules()
    rule = find_rule(rules, args.rule_name)
    if rule is None:
        known = ", ".join(r.name for r in rules)
        return fail(f"Unbekannter Punkt «{args.rule_name}». Möglich sind: {known}")
    print(render_explain(rule, load_law(), profiles, color=use_color(args), width=terminal_width()))
    return 0


def use_color(args: argparse.Namespace) -> bool:
    return not getattr(args, "no_color", False) and color_supported(sys.stdout)


def main(argv: list[str] | None = None) -> int:
    configure_output()
    profiles = load_profiles()
    args = build_parser(profiles).parse_args(argv)
    try:
        return run(args, profiles)
    except KeyboardInterrupt:
        print("lexshield: abgebrochen", file=sys.stderr)
        return 130
    except Exception as exc:  # exit 1 means "findings"; a crash must never look like that
        if os.environ.get("LEXSHIELD_DEBUG"):
            raise
        return fail(f"unerwarteter Fehler ({exc.__class__.__name__}: {exc}). Details mit LEXSHIELD_DEBUG=1.")


def run(args: argparse.Namespace, profiles: dict) -> int:
    if args.command == "scan":
        return cmd_scan(args, profiles)
    if args.command == "collect":
        return cmd_collect(args)
    if args.command == "explain":
        return cmd_explain(args, profiles)
    if args.command == "law":
        print(render_law(load_law(), load_rules(), color=use_color(args), width=terminal_width()))
        return 0
    if args.command == "rules":
        print(render_rules(load_rules(), width=terminal_width()))
        return 0
    print(render_profiles(profiles, load_rules(), width=terminal_width()))
    return 0
