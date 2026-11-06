"""Whole reports from the example facts."""

from datetime import date

from lexshield.engine import evaluate, load_rules


def statuses(report):
    return {f.rule.id: f.status for f in report.findings}


def test_solid_firm_passes_everything(solid):
    report = evaluate(solid, "klein")
    assert set(statuses(report).values()) == {"pass"}
    assert report.assessment() == "OK"
    assert not report.reaches("low")


def test_unverified_check_is_never_reported_as_nothing_open(solid):
    # An unchecked disk encryption must not read as "nothing open".
    solid["bitlocker"] = {"shell_value": 5}
    report = evaluate(solid)
    assert [f.rule.name for f in report.unverified()] == ["festplatte"]
    assert report.assessment() == "UNVOLLSTÄNDIG"
    assert report.verdict_level() == "high"
    assert report.reaches("high") and not report.reaches("critical")


def test_unverified_check_below_the_worst_finding_keeps_the_verdict(risky):
    risky["secure_boot"] = None  # medium, while critical findings are open
    report = evaluate(risky)
    assert "secure-boot" in [f.rule.name for f in report.unverified()]
    assert report.assessment() == "KRITISCH"


def test_nothing_readable_is_incomplete_not_low():
    report = evaluate({})
    assert report.assessment() == "UNVOLLSTÄNDIG"
    assert report.reaches("low") and report.ref_note == "Erhebungsdatum fehlt, Stichtag heute"


def test_sections_in_the_wrong_format_are_dropped_and_noted(risky):
    risky["host"] = "PC-01"
    risky["os"] = 7
    risky["defender"] = "x"
    report = evaluate(risky)
    assert report.facts["host"] is None and report.facts["os"] is None
    assert "host: unerwartetes Format, nicht ausgewertet" in report.facts["collector_errors"]
    assert not any(f.detail.startswith("Prüfung fehlgeschlagen") for f in report.findings)


def test_risky_firm_is_critical(risky):
    report = evaluate(risky, "klein")
    result = statuses(report)
    assert report.assessment() == "KRITISCH"
    expected_fail = {
        "LS-SYS-01", "LS-SYS-02", "LS-SYS-03", "LS-SYS-05", "LS-SYS-06", "LS-SYS-07",
        "LS-SYS-08", "LS-SYS-09", "LS-ACC-01", "LS-ACC-02", "LS-ACC-03", "LS-ACC-04", "LS-ACC-05",
        "LS-ACC-06", "LS-DAT-01", "LS-DAT-02", "LS-NET-01",
    }
    assert {rule for rule, status in result.items() if status == "fail"} == expected_fail
    assert result["LS-DAT-03"] == "warn"
    # Defender is off: how old its signatures are says nothing about protection.
    assert result["LS-SYS-04"] == "skip"


def test_every_rule_yields_exactly_one_finding(risky):
    assert [f.rule.id for f in evaluate(risky).findings] == [rule.id for rule in load_rules()]


def test_context_escalates_unencrypted_disk_with_documents(risky):
    finding = next(f for f in evaluate(risky).findings if f.rule.id == "LS-DAT-01")
    assert finding.rule.severity == "high"
    assert finding.severity == "critical"


def test_warning_counts_one_level_lower(risky):
    # Secure Boot on, but without the certificates of 2023: a warning on a medium rule.
    facts = {**risky, "secure_boot": 1, "secure_boot_ca2023": "NotStarted"}
    finding = next(f for f in evaluate(facts).findings if f.rule.id == "LS-SYS-06")
    assert finding.status == "warn" and finding.severity == "medium" and finding.weight == "low"


def test_profile_override_changes_severity(risky):
    small = next(f for f in evaluate(risky, "klein").findings if f.rule.id == "LS-ACC-02")
    solo = next(f for f in evaluate(risky, "einzel").findings if f.rule.id == "LS-ACC-02")
    large = next(f for f in evaluate(risky, "gross").findings if f.rule.id == "LS-ACC-01")
    assert small.severity == "medium"
    assert solo.severity == "low"
    assert large.severity == "high"


def test_reference_date_is_the_collection_date(risky):
    assert evaluate(risky).ref_date == date(2026, 11, 5)


def test_broken_fact_skips_the_rule_instead_of_crashing(solid):
    solid["lock"] = {"sleep_s": "not a dict"}
    solid["os"] = {"build": 26200, "edition_id": "Professional"}
    solid["updates"] = {"history": ["garbage", {"date": "nope"}]}
    report = evaluate(solid)
    assert len(report.findings) == len(load_rules())


def test_empty_facts_skip_without_crashing():
    report = evaluate({"collected_at": "2026-11-05T10:00:00+01:00"})
    assert len(report.findings) == len(load_rules())
    assert not any(f.detail.startswith("Prüfung fehlgeschlagen") for f in report.findings)


def test_cited_norms_follow_the_issues(risky, solid):
    assert evaluate(solid).cited_norms() == []
    cited = evaluate(risky).cited_norms()
    assert "stgb321" in cited and "dsg8" in cited


def test_verdict_phrase_names_how_soon():
    from lexshield.report import verdict_phrase

    rules = [rule for rule in load_rules() if rule.name in ("downloads", "llmnr")]
    facts = {"collected_at": "2026-11-05T09:00:00", "network": {"llmnr_policy": None},
             "local_docs": {"desktop": {"documents": 500, "older_than_30_days": 0}}}
    report = evaluate(facts, rules=rules)
    assert report.assessment() == "GERING" and verdict_phrase(report) == "nur Kleinigkeiten offen"
