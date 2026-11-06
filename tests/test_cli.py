"""End to end through the command line, using the example facts."""

import json

import pytest
from conftest import EXAMPLES

from lexshield.cli import main
from lexshield.engine import load_rules

RISKY = str(EXAMPLES / "kanzlei-riskant.json")
SOLID = str(EXAMPLES / "kanzlei-solide.json")


def test_scan_risky_exits_1_and_reports_critical(capsys):
    assert main(["scan", "--facts", RISKY, "--no-color"]) == 1
    out = capsys.readouterr().out
    assert "KRITISCH" in out
    assert "Windows 10 Pro 22H2" in out
    assert "\x1b[" not in out


def test_scan_solid_exits_0(capsys):
    assert main(["scan", "--facts", SOLID, "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "Gesamt      OK  keine offenen Punkte" in out
    assert "Nur dieses Gerät." in out  # a clean device is not a clean firm


def test_fail_on_never_always_exits_0():
    assert main(["scan", "--facts", RISKY, "--fail-on", "never"]) == 0


def test_brief_shows_only_issues(capsys):
    main(["scan", "--facts", SOLID, "--brief", "--no-color"])
    out = capsys.readouterr().out
    assert not any(line.startswith("  OK ") for line in out.splitlines())
    assert not any(rule.title in out for rule in load_rules())


def test_brief_still_shows_what_could_not_be_checked(tmp_path, capsys):
    facts = json.loads((EXAMPLES / "kanzlei-solide.json").read_text(encoding="utf-8"))
    facts["bitlocker"] = {"shell_value": 5}
    path = tmp_path / "t.json"
    path.write_text(json.dumps(facts), encoding="utf-8")
    assert main(["scan", "--facts", str(path), "--brief", "--no-color"]) == 1  # high, unchecked
    out = capsys.readouterr().out
    assert "Gesamt      UNVOLLSTÄNDIG  Festplattenverschlüsselung nicht prüfbar" in out
    assert out.count("Festplattenverschlüsselung") == 3  # finding, verdict, list "Nicht prüfbar"


def test_marks_show_urgency_not_status(solid):
    # A paused antivirus is a warning on a critical rule and counts as high; a missing
    # screen lock is a failure on a medium rule. Colouring by status would show the
    # first one yellow and the second one red, the wrong way round.
    from lexshield.engine import evaluate
    from lexshield.report import MARK_COLOR, render_terminal

    solid["antivirus"]["products"] = [{"name": "AV", "product_state": 270336}]  # 0x42000: snoozed
    solid["defender"]["realtime"] = False
    solid["lock"] = {"sleep_s": {"ac": 0, "dc": 0}}
    report = evaluate(solid)
    weights = {f.rule.id: (f.status, f.weight) for f in report.findings}
    assert weights["LS-SYS-03"] == ("warn", "high")
    assert weights["LS-ACC-06"] == ("fail", "medium")

    lines = render_terminal(report, color=True).splitlines()
    av_line = next(line for line in lines if "Virenschutz\x1b" in line)
    lock_line = next(line for line in lines if "Bildschirmsperre\x1b" in line)
    assert f"\x1b[{MARK_COLOR['high']}mHOCH\x1b[0m" in av_line
    assert f"\x1b[{MARK_COLOR['medium']}mMITTEL\x1b[0m" in lock_line


def test_colour_scale_runs_from_red_to_yellow():
    from lexshield.report import MARK_COLOR

    assert MARK_COLOR["high"].endswith(";196")  # red
    assert MARK_COLOR["medium"].endswith(";208")  # orange
    assert MARK_COLOR["low"].endswith(";178")  # yellow


def test_json_and_markdown_reports(tmp_path, capsys):
    json_path, md_path = tmp_path / "r.json", tmp_path / "r.md"
    main(["scan", "--facts", RISKY, "--json", str(json_path), "--md", str(md_path)])
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["assessment"] == "KRITISCH"
    assert len(data["findings"]) == len(load_rules())
    assert data["findings"][0]["weight"] == "critical"
    critical = data["findings"][0]
    assert critical["legal"] and critical["norms"] and critical["duties"]
    assert {d["duty"] for d in data["duties"]} >= set(critical["duties"])
    markdown = md_path.read_text(encoding="utf-8")
    assert "## Zu tun, nach Dringlichkeit" in markdown
    assert "**Recht:**" in markdown and "## Rechtliche Einordnung" in markdown
    assert "Art. 321 Ziff. 1 StGB" in markdown and "### Wer gebunden ist" in markdown
    assert "\N{NO-BREAK SPACE}" not in markdown


def test_saved_facts_round_trip(tmp_path, capsys):
    saved = tmp_path / "facts.json"
    main(["scan", "--facts", RISKY, "--save-facts", str(saved)])
    assert json.loads(saved.read_text(encoding="utf-8"))["host"]["name"] == "KANZLEI-PC-03"


def test_explain_shows_legal_framework(capsys):
    assert main(["explain", "ls-dat-01"]) == 0
    out = capsys.readouterr().out
    assert "Art. 321 Ziff. 1 StGB" in out and "Eventualvorsatz" in out
    # Norms stand under the duty they serve, in the order of norms.toml.
    assert out.index("BERUFSGEHEIMNIS") < out.index("DATENSICHERHEIT") < out.index("MELDEPFLICHT")
    assert "Recht " in out and "lexshield law" in out


def test_every_open_finding_states_its_legal_meaning(capsys):
    from lexshield.engine import evaluate, load_law
    from lexshield.report import render_terminal

    report = evaluate(json.loads((EXAMPLES / "kanzlei-riskant.json").read_text(encoding="utf-8")))
    out = render_terminal(report, law=load_law())
    assert out.count("Recht    ") == len(report.issues())
    assert "Normen   " not in out  # the chain of norms lives in explain, law and --verbose
    verbose = render_terminal(report, law=load_law(), mode="verbose")
    assert verbose.count("Normen   ") == len(report.findings)


def test_summary_names_the_duties_that_are_touched(capsys):
    main(["scan", "--facts", RISKY, "--no-color"])
    out = capsys.readouterr().out
    summary = out[out.index("RECHTLICH BETROFFEN"):]
    for label in ("Berufsgeheimnis", "Datensicherheit", "Sorgfalt und Haftung", "Meldepflicht"):
        assert label in summary
    assert "Betroffen: Festplattenverschlüsselung" in summary
    assert "Betroffen: alle 18 offenen Punkte" in summary  # every check serves data security


def test_no_legal_summary_without_open_findings(solid):
    from lexshield.engine import evaluate
    from lexshield.report import render_terminal

    report = evaluate(solid)
    assert not report.issues()  # the solid example has nothing open
    out = render_terminal(report)
    assert "RECHTLICH BETROFFEN" not in out and "keine offenen Punkte" in out


def test_norm_references_never_break_across_lines(capsys):
    for argv in (["scan", "--facts", RISKY, "--no-color", "--verbose"], ["explain", "festplatte"], ["law", "--no-color"]):
        main(argv)
        for line in capsys.readouterr().out.splitlines():
            assert not line.rstrip().endswith((" Art.", " Abs.", " lit.", " Ziff.")), line


@pytest.mark.parametrize("width", [20, 30, 40, 60])
def test_a_reference_stays_on_one_line(width):
    from lexshield.report import wrap

    references = [
        "Art. 3 Abs. 2 lit. a DSV", "Art. 321 Ziff. 1 Abs. 3 StGB", "Art. 2 Abs. 1 BGFA", "BGE 130 II 270 E. 3.2",
        "Art. 321 N 19", "Fn. 15", "25 ff.", "250 000", "Ziff. III.4.C", "Abs. 5 lit. a DSG", "Art. 394 ff. OR",
    ]
    text = "Siehe " + ", dann ".join(references) + "."
    lines = [line.replace("\N{NO-BREAK SPACE}", " ") for line in wrap(text, width, 0)]
    for reference in references:
        assert any(reference in line for line in lines), (reference, lines)


def test_law_lists_duties_norms_acts_and_questions(capsys):
    from lexshield.engine import load_law

    assert main(["law", "--no-color"]) == 0
    out = capsys.readouterr().out.replace("\N{NO-BREAK SPACE}", " ")
    law = load_law()
    assert all(duty["label"].upper() in out for duty in law["duty"].values())
    assert all(norm["ref"] in out for norm in law["norm"].values())
    assert all(act["url"] in out for act in law["act"].values())
    assert all(question["title"] in out for question in law["question"])
    assert "Geprüft bei: festplatte" in out


def test_explain_finds_short_name_title_and_id(capsys):
    for query in ("virenschutz", "Virenschutz", "VIRENSCHUTZ", "ls-sys-03"):
        assert main(["explain", query]) == 0
        out = capsys.readouterr().out
        assert "Virenschutz" in out and "Virenschutz-Updates" not in out
    assert main(["explain", "Festplattenverschlüsselung"]) == 0
    assert "festplatte" in capsys.readouterr().out


def test_explain_unknown_rule_exits_2_and_lists_names(capsys):
    assert main(["explain", "LS-XXX-99"]) == 2
    assert "virenschutz" in capsys.readouterr().err


def test_terminal_shows_short_names_not_ids(capsys):
    main(["scan", "--facts", RISKY, "--no-color"])
    out = capsys.readouterr().out
    assert "LS-" not in out
    # Both are critical; switching the virus protection on is the quick fix, so it comes first.
    assert "lexshield explain virenschutz" in out


def test_rules_and_profiles_list(capsys):
    main(["rules"])
    out = capsys.readouterr().out
    assert all(rule.name in out for rule in load_rules())
    assert "LS-" not in out
    main(["profiles"])
    assert "Einzelkanzlei" in capsys.readouterr().out


def test_unreadable_facts_exit_2(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    for content in ("{not json", "[]", "42", "[" * 100_000, '{"os": {"build": ' + "9" * 5000 + "}}"):
        bad.write_text(content, encoding="utf-8")
        assert main(["scan", "--facts", str(bad)]) == 2, content[:20]
        assert "Traceback" not in capsys.readouterr().err


def test_facts_saved_by_windows_powershell_are_read(tmp_path, capsys):
    # Windows PowerShell 5.1 writes UTF-16 with ">", ANSI with Out-File -Encoding Default.
    text = (EXAMPLES / "kanzlei-riskant.json").read_text(encoding="utf-8").replace("KANZLEI-PC-03", "ZÜRICH-PC")
    for encoding in ("utf-16", "cp1252", "utf-8-sig"):
        path = tmp_path / f"{encoding}.json"
        path.write_text(text, encoding=encoding)
        assert main(["scan", "--facts", str(path), "--no-color"]) == 1, encoding
        assert "ZÜRICH-PC" in capsys.readouterr().out


def test_unwritable_output_fails_before_the_audit(tmp_path, capsys):
    missing = str(tmp_path / "gibtsnicht" / "b.json")
    for option in ("--json", "--md", "--save-facts"):
        assert main(["scan", "--facts", SOLID, option, missing]) == 2
        captured = capsys.readouterr()
        assert "gibt es nicht" in captured.err and captured.out == ""
    assert main(["scan", "--facts", SOLID, "--json", str(tmp_path)]) == 2
    assert "ist ein Ordner" in capsys.readouterr().err


def test_control_characters_in_facts_do_not_reach_the_output(tmp_path, capsys):
    facts = json.loads((EXAMPLES / "kanzlei-riskant.json").read_text(encoding="utf-8"))
    facts["host"]["name"] = "PC\x1b[2K\n\n## Alles in Ordnung"
    path, md = tmp_path / "t.json", tmp_path / "r.md"
    path.write_text(json.dumps(facts), encoding="utf-8")
    main(["scan", "--facts", str(path), "--no-color", "--md", str(md)])
    assert "\x1b" not in capsys.readouterr().out
    assert "\n## Alles in Ordnung" not in md.read_text(encoding="utf-8")


def test_reports_carry_notes_and_read_errors(tmp_path, capsys):
    facts = json.loads((EXAMPLES / "kanzlei-solide.json").read_text(encoding="utf-8"))
    facts["collected_at"] = "05.11.2026 09:12"
    facts["collector_errors"] = ["powercfg: Fehler 0x5"]
    facts["host"]["elevated"] = False
    path, md, js = tmp_path / "t.json", tmp_path / "r.md", tmp_path / "r.json"
    path.write_text(json.dumps(facts), encoding="utf-8")
    main(["scan", "--facts", str(path), "--no-color", "--md", str(md), "--json", str(js)])
    out, markdown, data = capsys.readouterr().out, md.read_text(encoding="utf-8"), json.loads(js.read_text(encoding="utf-8"))
    for text in (" ".join(out.split()), markdown):  # the terminal wraps long lines
        assert "Erhebungsdatum unlesbar, Stichtag heute" in text
        assert "nicht als Administrator gestartet" in text
        assert "powercfg: Fehler 0x5" in text
    assert data["reference_note"] == "Erhebungsdatum unlesbar, Stichtag heute"
    assert data["elevated"] is False and data["collector_errors"] == ["powercfg: Fehler 0x5"]


def test_crash_is_exit_2_not_exit_1(monkeypatch, capsys):
    import lexshield.cli as cli

    def boom(*args, **kwargs):
        raise RuntimeError("kaputt")

    monkeypatch.setattr(cli, "render_terminal", boom)
    assert main(["scan", "--facts", RISKY]) == 2
    assert "unerwarteter Fehler (RuntimeError: kaputt)" in capsys.readouterr().err


def test_the_to_do_list_comes_last_and_says_who_fixes_what(capsys, tmp_path):
    main(["scan", "--facts", RISKY, "--no-color"])
    out = capsys.readouterr().out
    # Legal summary, then the result, then the to-do list: what is left on screen is what to do.
    assert out.index("RECHTLICH BETROFFEN") < out.index("ERGEBNIS") < out.index("Zu tun, das Dringendste zuerst")
    assert "KRITISCH  4 Punkte sofort beheben" in out
    todo = out[out.index("Zu tun"):].splitlines()
    first, second = todo[1].split(), todo[2].split()
    assert first[:2] == ["KRITISCH", "Virenschutz"] and first[-2:] == ["selbst", "virenschutz"]
    assert second[-2:] == ["IT-Betreuung", "windows"]
    assert "Für IT" in out and "Mitglieder des Schweizerischen Anwaltsverbands" in " ".join(out.split())
    md, js = tmp_path / "r.md", tmp_path / "r.json"
    main(["scan", "--facts", RISKY, "--no-color", "--md", str(md), "--json", str(js)])
    text = md.read_text(encoding="utf-8")
    assert "**KRITISCH** – 4 Punkte sofort beheben" in text and "- **Für IT:**" in text
    data = json.loads(js.read_text(encoding="utf-8"))
    assert data["assessment_text"] == "4 Punkte sofort beheben"
    assert {f["who"] for f in data["findings"]} == {"selbst", "it"}


ESC = chr(27)
VIEWS = (
    ["scan", "--facts", RISKY],
    ["scan", "--facts", RISKY, "--verbose"],
    ["scan", "--facts", SOLID, "--brief"],
    ["explain", "festplatte"],
    ["explain", "bildschirmsperre"],
    ["law"],
    ["rules"],
    ["profiles"],
)


def test_no_color_is_accepted_everywhere_and_switches_colour_off(monkeypatch, capsys):
    import lexshield.cli as cli

    monkeypatch.setattr(cli, "color_supported", lambda stream: True)  # as in a real terminal
    for argv in VIEWS:
        main([*argv, "--no-color"])
        assert ESC not in capsys.readouterr().out, argv
    for argv in (["scan", "--facts", RISKY], ["explain", "festplatte"], ["law"]):
        main(argv)
        assert ESC in capsys.readouterr().out, argv


@pytest.mark.parametrize("columns", [60, 70, 80, 92, 200])
def test_every_view_fits_the_terminal(monkeypatch, capsys, columns):
    # Never wider than the terminal, and never wider than 92 columns, which read well.
    # Words are never cut, so two kinds of line may stick out: URLs, which stay clickable,
    # and in the narrowest view of the rules a long title word next to its columns.
    monkeypatch.setenv("COLUMNS", str(columns))
    limit = min(max(columns, 60), 92)
    for argv in VIEWS:
        main([*argv, "--no-color"])
        for line in capsys.readouterr().out.splitlines():
            if len(line) <= limit or "https://" in line:
                continue
            assert argv == ["rules"] and columns == 60, (argv, line)
            assert " " not in line.rstrip().rsplit("  ", 1)[-1], line  # only the title, unbroken


def test_characters_the_console_lacks_stay_readable():
    from lexshield.cli import PLAIN

    text = "Art.\N{NO-BREAK SPACE}8 \N{EN DASH} Kanzlei \N{RIGHTWARDS ARROW} hoch\N{HORIZONTAL ELLIPSIS} \N{LEFT-POINTING DOUBLE ANGLE QUOTATION MARK}ok\N{RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK} \N{CHECK MARK}"
    assert text.encode("ascii", errors="lexshield") == b'Art. 8 - Kanzlei -> hoch... "ok" ?'
    # Code page 850, the usual one in Switzerland, keeps umlauts and guillemets as they are.
    umlauts = "Prüfung \N{EN DASH} «Berufsgeheimnis»"
    assert umlauts.encode("cp850", errors="lexshield").decode("cp850") == "Prüfung - «Berufsgeheimnis»"
    assert all(len(char) == 1 for char in PLAIN)


def test_explain_says_who_and_when_the_severity_rises(capsys):
    main(["explain", "festplatte"])
    out = capsys.readouterr().out
    assert "hoch; kritisch, wenn in Downloads oder auf dem Desktop Dokumente liegen" in out
    assert "IT-Betreuung" in out and "Für IT" in out
