"""Output: terminal text, Markdown and JSON."""

from __future__ import annotations

import re
import textwrap
from datetime import datetime

from . import __version__
from .checks import as_bool, windows_name
from .engine import CATEGORIES, RANK, VERDICT_INCOMPLETE, Finding, Report, Rule, load_law, profile_overrides

SEVERITY_DE = {"critical": "kritisch", "high": "hoch", "medium": "mittel", "low": "gering"}

# Each finding gets one mark: how urgent it is, or OK, or a dash when it could not be checked.
MARK = {"critical": "KRITISCH", "high": "HOCH", "medium": "MITTEL", "low": "GERING", "pass": "OK", "skip": "–"}
# Fixed entries of the 256-colour palette, so no terminal theme can reorder the scale:
# the more urgent, the warmer the colour.
MARK_COLOR = {
    "critical": "1;97;48;5;160",  # white on red
    "high": "1;38;5;196",  # red
    "medium": "1;38;5;208",  # orange
    "low": "38;5;178",  # yellow
    "pass": "32",  # green
    "skip": "90",  # grey
}
OK_COLOR = "32"
DISCLAIMER = (
    "LexShield liest nur Einstellungen und ändert nichts. "
    "Kein Ersatz für eine Prüfung durch Fachleute und keine Rechtsberatung."
)
# A clean report must not read as "the firm is secure".
SCOPE = "Nur dieses Gerät. Andere Kanzlei-Geräte, Datensicherung, E-Mail und Cloud prüft LexShield nicht."
# Who usually fixes a finding, shown next to it so the quick fixes are not lost among the projects.
WHO = {"selbst": "selbst", "it": "IT-Betreuung"}
WHO_WIDTH = 14  # "IT-Betreuung  "
SSR_NOTE = (
    "Die Standesregeln (SSR) sind nur für Mitglieder des Schweizerischen Anwaltsverbands verbindlich. "
    "Gerichte ziehen sie zur Auslegung des Anwaltsgesetzes heran, soweit sie eine landesweite Auffassung ausdrücken."
)
# The verdict in one phrase: what to do, and how soon. The time frames are LexShield's convention.
VERDICT_PHRASE = {
    "critical": "{n} sofort beheben",
    "high": "{n} in den nächsten Tagen beheben",
    "medium": "keine dringende Lücke, {n} bei Gelegenheit beheben",
    "low": "nur Kleinigkeiten offen",
}

# Layout grid: marks and labels start at PAD, all text starts at TEXT.
PAD = 2
MARK_WIDTH = 10  # " KRITISCH " on its red background
TEXT = PAD + MARK_WIDTH + 2
LABEL = 9  # "Was tun  "
DUTY_LABEL = 22  # "Sorgfalt und Haftung  "
REF_LABEL = 26  # "Art. 3 Abs. 2 lit. a DSV  "
MAX_WIDTH = 92  # longer lines are harder to read


class Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.enabled and text else text

    def bold(self, text: str) -> str:
        return self(text, "1")

    def dim(self, text: str) -> str:
        return self(text, "2")


# What must never break across lines in running text: a reference such as
# "Art. 3 Abs. 2 lit. a DSV" or "BGE 130 II 270 E. 3.2", "N 19", "25 ff." and "250 000".
ACTS = r"BGFA|SSR|StGB|DSG|DSV|OR|BGÖ"
CITATION = re.compile(
    r"\b(?:Art\. \d+[a-z]?|Abs\. \d+|lit\. [a-z]|Ziff\. \d+)"
    r"(?: (?:Abs\.|Ziff\.|lit\.) [0-9a-z]+)*(?: ff?\.)?(?: (?:" + ACTS + r")\b)?(?: N \d+)?"
    r"|\bBGE \d+ [IVX]+ \d+(?: E\. \d[\d.]*)?"
    r"|\b(?:N|Fn\.|E\.) \d[\d.]*"
    r"|\bZiff\. [\w.]*\w"
    r"|\b\d+ ff?\."
    r"|\b\d{1,3}(?: \d{3})+\b"
)


def bind(match: re.Match) -> str:
    return match.group().replace(" ", "\N{NO-BREAK SPACE}")


def wrap(text: str, width: int, indent: int, label: str = "", label_width: int = LABEL) -> list[str]:
    first = " " * indent + (label.ljust(label_width) if label else "")
    rest = " " * (indent + (label_width if label else 0))
    text = CITATION.sub(bind, text)
    # Words are never cut, not even at hyphens: German compounds such as
    # "BitLocker-Laufwerkverschlüsselung" stay whole, and so do URLs, which stay clickable.
    return textwrap.wrap(
        text, width=width, initial_indent=first, subsequent_indent=rest,
        break_on_hyphens=False, break_long_words=False,
    ) or [first.rstrip()]


def labeled(
    style: Style, label: str, text: str, width: int, indent: int = TEXT, label_width: int = LABEL,
    strong: bool = False,
) -> list[str]:
    """Wrapped text with a label in front of the first line: dimmed, or bold when strong."""
    lines = wrap(text, width, indent, label, label_width)
    styled = style.bold(label) + " " * (label_width - len(label)) if strong else style.dim(label.ljust(label_width))
    lines[0] = " " * indent + styled + lines[0][indent + label_width:]
    return lines


def dimmed(style: Style, text: str, width: int, indent: int) -> list[str]:
    return [style.dim(line) for line in wrap(text, width, indent)]


def format_stamp(stamp: object) -> str:
    try:
        return datetime.fromisoformat(str(stamp)).strftime("%d.%m.%Y %H:%M")
    except ValueError:
        return str(stamp or "unbekannt")


def mark(style: Style, key: str) -> str:
    word = MARK[key]
    if key == "critical" and style.enabled:  # white on red: the box starts where the other marks start
        return style(f" {word} ", MARK_COLOR[key]) + " " * (MARK_WIDTH - len(word) - 2)
    return style(word, MARK_COLOR[key]) + " " * (MARK_WIDTH - len(word))


def right(left: str, left_len: int, text: str, width: int) -> str:
    """Place text at the right edge; left_len is the visible length of left."""
    return left + " " * max(2, width - left_len - len(text))


def points(n: int) -> str:
    return "1 Punkt" if n == 1 else f"{n} Punkte"


def verdict_phrase(report: Report) -> str:
    """What the verdict means in practice, e.g. "2 Punkte sofort beheben"."""
    assessment, level = report.assessment(), report.verdict_level()
    if level is None:
        return "keine offenen Punkte"
    if assessment == VERDICT_INCOMPLETE:
        return f"{report.unverified()[0].rule.title} nicht prüfbar"
    issues = report.issues()
    # Urgent levels count only their own points; below that, everything open can wait.
    n = sum(f.weight == level for f in issues) if level in ("critical", "high") else len(issues)
    return VERDICT_PHRASE[level].format(n=points(n))


def tally(findings: list[Finding]) -> str:
    ok = sum(f.status == "pass" for f in findings)
    open_ = sum(bool(f.weight) for f in findings)
    unclear = sum(f.status == "skip" for f in findings)
    parts = [f"{ok} in Ordnung"] if ok or not (open_ or unclear) else []
    if open_:
        parts.append(f"{open_} offen")
    if unclear:
        parts.append(f"{unclear} nicht prüfbar")
    return ", ".join(parts)


# --------------------------------------------------------------------------- legal references


def nb(text: str) -> str:
    """No-break spaces keep a reference such as "Art. 3 Abs. 2 lit. f DSV" on one line."""
    return text.replace(" ", "\N{NO-BREAK SPACE}")


def short_ref(ref: str) -> str:
    """"Art. 3 Abs. 2 lit. f DSV" -> "Art. 3 DSV", for summaries that name each article once."""
    return re.sub(r" (Abs\.|lit\.|Ziff\.) \S+", "", ref)


def refs(keys: list[str], norms: dict, short: bool = False) -> str:
    cited: list[str] = []
    for key in keys:
        if key in norms:
            ref = short_ref(norms[key]["ref"]) if short else norms[key]["ref"]
            if ref not in cited:
                cited.append(ref)
    return " · ".join(nb(ref) for ref in cited)


def affected(findings: list[Finding], issues: list[Finding]) -> str:
    """The findings under a duty; when every open finding is there, say so instead of listing them."""
    if len(findings) == len(issues) > 1:
        return f"Betroffen: alle {len(issues)} offenen Punkte"
    return "Betroffen: " + ", ".join(f.rule.title for f in findings)


def by_duty(keys: list[str], law: dict) -> list[tuple[str, list[str]]]:
    """Norm keys grouped by duty, in the order of norms.toml."""
    norms = law["norm"]
    return [
        (duty, [k for k in norms if k in keys and norms[k]["duty"] == duty])
        for duty in law["duty"]
        if any(norms[k]["duty"] == duty for k in keys if k in norms)
    ]


# --------------------------------------------------------------------------- terminal


def render_terminal(
    report: Report, *, color: bool = False, width: int = MAX_WIDTH, mode: str = "normal", law: dict | None = None
) -> str:
    style = Style(color)
    width = fit(width)
    law = law or load_law()
    facts = report.facts
    host = facts.get("host") or {}
    checked = format_stamp(facts.get("collected_at"))
    if report.ref_note:
        checked += f" · {report.ref_note}"
    if as_bool(host.get("elevated")) is False:
        checked += " · nicht als Administrator gestartet"
    if as_bool(host.get("other_user")) and host.get("session_user"):
        checked += f" · Einstellungen des angemeldeten Kontos {host['session_user']}"

    name, tagline, version = "LEXSHIELD", "Sicherheitscheck für Anwaltskanzleien", f"v{__version__}"
    title = " " * PAD + style.bold(name) + "  " + tagline
    lines = [
        "",
        right(title, PAD + len(name) + 2 + len(tagline), version, width) + style.dim(version),
        "",
        *labeled(style, "Gerät", str(host.get("name") or "unbekannt"), width, PAD, TEXT - PAD),
        *labeled(style, "System", windows_name(facts.get("os") or {}), width, PAD, TEXT - PAD),
        *labeled(style, "Profil", f"{report.profile['label']} ({report.profile['size']})", width, PAD, TEXT - PAD),
        *labeled(style, "Geprüft", checked, width, PAD, TEXT - PAD),
    ]

    for key, label in CATEGORIES.items():
        findings = [f for f in report.findings if f.rule.category == key]
        # --brief hides what is in order, not what could not be checked.
        shown = [f for f in findings if mode != "brief" or f.weight or f.status == "skip"]
        if not shown:
            continue
        heading = label.upper()
        summary = tally(findings)
        lines += [
            "",
            "",
            right(" " * PAD + style.bold(heading), PAD + len(heading), summary, width) + style.dim(summary),
            "",
        ]
        previous_block = False
        for finding in shown:
            # Findings with an explanation stand apart; plain OK lines stay together.
            block = bool(finding.weight) or mode == "verbose"
            if (block or previous_block) and lines[-1]:
                lines.append("")
            lines += finding_lines(finding, style, width, mode, law["norm"])
            previous_block = block

    lines += ["", ""] + summary_lines(report, style, width, law)
    return "\n".join(lines)


def finding_lines(finding: Finding, style: Style, width: int, mode: str, norms: dict) -> list[str]:
    key = finding.weight or finding.status
    rule = finding.rule
    head = " " * PAD + mark(style, key) + "  "
    if finding.weight:  # open: who fixes it, at the right edge; below the title when it does not fit
        who = WHO[rule.who]
        if TEXT + len(rule.title) + 2 + len(who) <= width:
            lines = [right(head + style.bold(rule.title), TEXT + len(rule.title), who, width) + who]
        else:
            lines = [head + style.bold(rule.title), " " * (width - len(who)) + who]
    else:
        lines = [head + rule.title]
    detail = []
    if finding.detail.casefold() != rule.title.casefold():
        detail = wrap(finding.detail, width, TEXT)
    lines += detail if finding.weight else [style.dim(line) for line in detail]
    if finding.weight or mode == "verbose":
        lines.append("")
        lines += labeled(style, "Warum", rule.why, width)
        lines += labeled(style, "Was tun", rule.fix, width)
        if rule.fix_it:
            lines += labeled(style, "Für IT", rule.fix_it, width)
        lines += labeled(style, "Recht", rule.legal, width)
    if mode == "verbose":  # the chain of norms lives in explain, law and the reports
        lines += [style.dim(line) for line in wrap(refs(list(rule.norms), norms), width, TEXT, "Normen")]
    return lines


def list_line(style: Style, finding: Finding, key: str, width: int, who: str, name_width: int) -> list[str]:
    """A finding in a summary list: mark and title, then who fixes it and the short name in columns.

    When the columns do not fit next to the title, they move to the next line, in the same place.
    """
    title, name = finding.rule.title, finding.rule.name
    head = " " * PAD + mark(style, key) + "  " + title
    column = max(TEXT, width - WHO_WIDTH - name_width)
    if TEXT + len(title) + 2 > column:
        return [head, " " * column + who.ljust(WHO_WIDTH) + style.dim(name)]
    return [head + " " * (column - TEXT - len(title)) + who.ljust(WHO_WIDTH) + style.dim(name)]


def summary_lines(report: Report, style: Style, width: int, law: dict) -> list[str]:
    """Legal summary first, then the result; the to-do list comes last, where the terminal stops."""
    issues, unverified = report.issues(), report.unverified()
    assessment, level = report.assessment(), report.verdict_level()
    if level is None:
        verdict = style(assessment, OK_COLOR)
    else:
        pill = f" {assessment} " if level == "critical" and style.enabled else assessment
        verdict = style(pill, MARK_COLOR[level])
    lines = [*legal_summary(report, style, width, law), "", ""] if issues else []
    lines += [
        " " * PAD + style.bold("ERGEBNIS"),
        "",
        " " * PAD + style.dim("Gesamt".ljust(TEXT - PAD)) + verdict + "  " + verdict_phrase(report),
        *labeled(style, "Punkte", f"{len(report.findings)} geprüft: {tally(report.findings)}", width, PAD, TEXT - PAD),
        *labeled(style, "Umfang", SCOPE, width, PAD, TEXT - PAD),
    ]
    errors = report.facts.get("collector_errors") or []
    if errors:
        lines += labeled(style, "Lesefehler", "; ".join(errors), width, PAD, TEXT - PAD)
    name_width = max((len(f.rule.name) for f in issues + unverified), default=0)
    if unverified:
        lines += ["", " " * PAD + "Nicht prüfbar"]
        for finding in unverified:
            lines += list_line(style, finding, "skip", width, "", name_width)
        if as_bool((report.facts.get("host") or {}).get("elevated")) is False:
            lines += labeled(style, "Hinweis", "Als Administrator starten, um mehr prüfen zu können", width, PAD, TEXT - PAD)
    if issues:
        lines += ["", " " * PAD + "Zu tun, das Dringendste zuerst"]
        for finding in issues:
            lines += list_line(style, finding, finding.weight, width, WHO[finding.rule.who], name_width)
        lines += ["", *labeled(style, "Mehr dazu", f"lexshield explain {issues[0].rule.name}", width, PAD, TEXT - PAD)]
    lines += ["", *dimmed(style, DISCLAIMER, width, PAD), ""]
    return lines


def legal_summary(report: Report, style: Style, width: int, law: dict) -> list[str]:
    """Which duties the open findings touch: duty, what it means, which findings, which norms."""
    lines = [" " * PAD + style.bold("RECHTLICH BETROFFEN"), ""]
    indent = PAD + DUTY_LABEL
    for key, findings, keys in report.duties(law):
        duty = law["duty"][key]
        lines += labeled(style, duty["label"], duty["text"], width, PAD, DUTY_LABEL, strong=True)
        lines += wrap(affected(findings, report.issues()), width, indent)
        lines += dimmed(style, refs(keys, law["norm"], short=True), width, indent)
        lines.append("")
    # The SSR bind only members of the bar association; say so once, where they are cited.
    if any(law["norm"][k]["act"] == "ssr" for k in report.cited_norms() if k in law["norm"]):
        lines += [*dimmed(style, SSR_NOTE, width, PAD + DUTY_LABEL), ""]
    lines += labeled(style, "Mehr dazu", "lexshield law  (Rechtsrahmen, wer gebunden ist, offene Fragen)",
                     width, PAD, DUTY_LABEL)
    return lines


# --------------------------------------------------------------------------- explain, law, rules, profiles

EXPLAIN_LABEL = 15  # "Dringlichkeit  "


def norm_lines(style: Style, keys: list[str], law: dict, width: int) -> list[str]:
    """Norms grouped under their duty, each with its text."""
    norms = law["norm"]
    lines = []
    for duty, group in by_duty(keys, law):
        lines += ["", " " * PAD + style.bold(law["duty"][duty]["label"].upper())]
        for key in group:
            norm = norms[key]
            lines += wrap(f"{norm['title']}. {norm['text']}", width, PAD, norm["ref"], REF_LABEL)
    return lines


def fit(width: int) -> int:
    """The terminal width, but no wider than reads well and no narrower than the grid needs."""
    return max(60, min(width, MAX_WIDTH))


def render_explain(rule: Rule, law: dict, profiles: dict, *, color: bool = False, width: int = MAX_WIDTH) -> str:
    style = Style(color)
    width = fit(width)
    severity = SEVERITY_DE[rule.severity]
    if rule.severity_note:
        severity += f"; {rule.severity_note}"
    differing = [
        f"{profile['label']}: {SEVERITY_DE[sev]}"
        for profile in profiles.values()
        for rule_id, sev in profile_overrides(profile).items()
        if rule_id == rule.id
    ]
    if differing:
        severity += " (abweichend: " + "; ".join(differing) + ")"
    lines = ["", " " * PAD + style.bold(rule.title), ""]
    for label, text in (
        ("Kurzname", rule.name),
        ("Bereich", CATEGORIES.get(rule.category, rule.category)),
        ("Dringlichkeit", severity),
        ("Wer", WHO[rule.who]),
        ("Warum", rule.why),
        ("Was tun", rule.fix),
        ("Für IT", rule.fix_it),
        ("Recht", rule.legal),
        ("Grundlage", rule.basis),
    ):
        if text:
            lines += labeled(style, label, text, width, PAD, EXPLAIN_LABEL)
    lines += norm_lines(style, list(rule.norms), law, width)
    lines += [
        "",
        *wrap("Text in «» ist Gesetzeswortlaut. Wer gebunden ist und offene Fragen: lexshield law", width, PAD),
        " " * PAD + "Keine Rechtsberatung.",
        "",
    ]
    return "\n".join(lines)


def render_law(law: dict, rules: list[Rule], *, color: bool = False, width: int = MAX_WIDTH) -> str:
    """The whole legal framework: duties with their norms, who is bound, open questions."""
    style = Style(color)
    width = fit(width)
    norms = law["norm"]
    checked = law["checked"].strftime("%d.%m.%Y")
    heading, note = "RECHTSRAHMEN", f"Wortlaut geprüft am {checked}"
    lines = [
        "",
        right(" " * PAD + style.bold(heading), PAD + len(heading), note, width) + style.dim(note),
        "",
        *wrap(
            f"LexShield ordnet jeden Befund einer oder mehreren von {len(law['duty'])} Pflichten zu. "
            "Text in «» ist Gesetzeswortlaut, alles andere eine Zusammenfassung. Keine Rechtsberatung.",
            width, PAD,
        ),
    ]
    checked_by = {key: [r.name for r in rules if key in r.norms] for key in norms}
    for duty_key, duty in law["duty"].items():
        lines += ["", "", " " * PAD + style.bold(duty["label"].upper()), *wrap(duty["text"], width, PAD), ""]
        for key, norm in norms.items():
            if norm["duty"] != duty_key:
                continue
            lines += wrap(f"{norm['title']}. {norm['text']}", width, PAD, norm["ref"], REF_LABEL)
            if checked_by[key]:
                lines += dimmed(style, "Geprüft bei: " + ", ".join(checked_by[key]), width, PAD + REF_LABEL)
    lines += ["", "", " " * PAD + style.bold("WER GEBUNDEN IST"), ""]
    for act in law["act"].values():
        lines += wrap(f"{act['title']}. {act['binds']}", width, PAD, act["name"], REF_LABEL)
        lines.append(" " * (PAD + REF_LABEL) + style.dim(act["url"]))  # URLs are never wrapped
    lines += ["", "", " " * PAD + style.bold("OFFENE RECHTSFRAGEN")]
    for question in law.get("question", []):
        lines += ["", " " * PAD + style.bold(question["title"]), *wrap(question["text"], width, PAD)]
        for source in question["sources"]:
            lines += dimmed(style, "Quelle: " + source, width, PAD)
    lines.append("")
    return "\n".join(lines)


def render_rules(rules: list[Rule], *, width: int = MAX_WIDTH) -> str:
    """One line per rule: short name, urgency, who fixes it, title.

    When space is short the column "Wer" goes, so that the longest word of a title still fits.
    """
    width = fit(width)
    name_width = max(len(rule.name) for rule in rules) + 2
    columns = [("Dringlichkeit", 15, lambda r: SEVERITY_DE[r.severity])]
    longest_word = max(len(word) for rule in rules for word in rule.title.split())
    if width - PAD - name_width - 15 - WHO_WIDTH >= longest_word:
        columns.append(("Wer", WHO_WIDTH, lambda r: WHO[r.who]))
    head = " " * PAD + "Kurzname".ljust(name_width) + "".join(label.ljust(size) for label, size, _ in columns)
    lines = ["", head + "Punkt", ""]
    for rule in rules:
        cells = rule.name.ljust(name_width) + "".join(value(rule).ljust(size) for _, size, value in columns)
        title = wrap(rule.title, width, PAD + len(cells))  # long titles continue under themselves
        lines += [" " * PAD + cells + title[0].lstrip(), *title[1:]]
    lines += ["", " " * PAD + "Mehr zu einem Punkt: lexshield explain KURZNAME", ""]
    return "\n".join(lines)


def render_profiles(profiles: dict, rules: list[Rule], *, width: int = MAX_WIDTH) -> str:
    width = fit(width)
    titles = {rule.id: rule.title for rule in rules}
    lines = [""]
    for key, profile in profiles.items():
        lines.append(" " * PAD + f"{key:<8}{profile['label']} ({profile['size']})")
        for item in profile.get("override", []):
            title = titles.get(item["rule"], item["rule"])
            lines += wrap(f"{title} → {SEVERITY_DE[item['severity']]}: {item['reason']}", width, PAD + 8)
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- files


def cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: Report, law: dict) -> str:
    norms = law["norm"]
    facts = report.facts
    host = facts.get("host") or {}
    profile = report.profile
    unverified = report.unverified()
    checked = format_stamp(facts.get("collected_at"))
    if report.ref_note:
        checked += f" ({report.ref_note})"
    if as_bool(host.get("elevated")) is False:
        checked += ", nicht als Administrator gestartet"
    verdict = f"**{report.assessment()}** – {verdict_phrase(report)}"
    lines = [
        "# LexShield – Sicherheitsbericht",
        "",
        "| | |",
        "| --- | --- |",
        f"| Gerät | {cell(str(host.get('name') or 'unbekannt'))} |",
        f"| System | {cell(windows_name(facts.get('os') or {}))} |",
        f"| Profil | {profile['label']} ({profile['size']}) |",
        f"| Geprüft | {cell(checked)} |",
        f"| Gesamt | {cell(verdict)} |",
        f"| Umfang | {SCOPE} |",
        "",
        "## Übersicht",
        "",
        "| Ergebnis | ID | Punkt | Befund |",
        "| --- | --- | --- | --- |",
    ]
    for f in report.findings:
        lines.append(f"| {MARK[f.weight or f.status]} | {f.rule.id} | {cell(f.rule.title)} | {cell(f.detail)} |")
    issues = report.issues()
    if issues:
        lines += ["", "## Zu tun, nach Dringlichkeit", ""]
        for f in issues:
            lines += [
                f"### {f.rule.id} {f.rule.title} ({SEVERITY_DE[f.weight]})",
                "",
                f"- **Befund:** {f.detail}",
                f"- **Wer:** {WHO[f.rule.who]}",
                f"- **Warum:** {f.rule.why}",
                f"- **Was tun:** {f.rule.fix}",
                *([f"- **Für IT:** {f.rule.fix_it}"] if f.rule.fix_it else []),
                f"- **Recht:** {f.rule.legal}",
                f"- **Normen:** {refs(list(f.rule.norms), norms).replace(chr(0xA0), ' ')}",
                f"- **Grundlage:** {f.rule.basis}",
                "",
            ]
        lines += ["## Rechtliche Einordnung", "", "_Text in «» ist Gesetzeswortlaut._", ""]
        for key, findings, keys in report.duties(law):
            duty = law["duty"][key]
            lines += [
                f"### {duty['label']}",
                "",
                duty["text"],
                "",
                affected(findings, issues),
                "",
            ]
            lines += [f"- **{norms[k]['ref']}** – {norms[k]['title']}. {norms[k]['text']}" for k in keys]
            lines.append("")
        acts = [a for a in law["act"] if any(norms[k]["act"] == a for k in report.cited_norms() if k in norms)]
        lines += ["### Wer gebunden ist", ""]
        if "ssr" in acts:
            lines += [SSR_NOTE, ""]
        lines += [f"- **{law['act'][a]['name']}:** {law['act'][a]['binds']}" for a in acts]
        lines.append("")
    if unverified:
        lines += ["## Nicht prüfbar", ""]
        lines += [f"- **{f.rule.id} {f.rule.title}** ({SEVERITY_DE[f.severity]}): {cell(f.detail)}" for f in unverified]
        lines.append("")
    errors = facts.get("collector_errors") or []
    if errors:
        lines += ["## Lesefehler der Erhebung", ""]
        lines += [f"- {cell(error)}" for error in errors]
        lines.append("")
    lines += ["---", "", f"_{DISCLAIMER} Erstellt mit LexShield {__version__}._", ""]
    return "\n".join(lines)


def report_to_dict(report: Report, law: dict) -> dict:
    norms = law["norm"]
    facts = report.facts
    return {
        "tool": "lexshield",
        "version": __version__,
        "collected_at": facts.get("collected_at"),
        "reference_date": report.ref_date.isoformat(),
        "reference_note": report.ref_note,
        "host": (facts.get("host") or {}).get("name"),
        "elevated": as_bool((facts.get("host") or {}).get("elevated")),
        "system": windows_name(facts.get("os") or {}),
        "profile": report.profile_key,
        "assessment": report.assessment(),
        "assessment_text": verdict_phrase(report),
        "counts": report.weight_counts(),
        "unverified": [f.rule.id for f in report.unverified()],
        "findings": [
            {
                "id": f.rule.id,
                "name": f.rule.name,
                "category": f.rule.category,
                "title": f.rule.title,
                "status": f.status,
                "severity": f.severity,
                "weight": f.weight,
                "detail": f.detail,
                "who": f.rule.who,
                "risk": f.rule.why,
                "fix": f.rule.fix,
                "fix_it": f.rule.fix_it or None,
                "legal": f.rule.legal,
                "basis": f.rule.basis,
                "norms": [norms[key]["ref"] for key in f.rule.norms if key in norms],
                "duties": [duty for duty, _ in by_duty(list(f.rule.norms), law)],
            }
            for f in sorted(report.findings, key=lambda f: (RANK[f.weight] if f.weight else 9, f.rule.id))
        ],
        "duties": [
            {"duty": key, "label": law["duty"][key]["label"], "findings": [f.rule.id for f in findings]}
            for key, findings, _ in report.duties(law)
        ],
        "collector_errors": facts.get("collector_errors") or [],
    }
