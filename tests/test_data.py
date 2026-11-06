"""The rule, profile, norm and lifecycle files are consistent."""

import re
from datetime import date

from lexshield.checks import CHECKS
from lexshield.engine import (
    CATEGORIES,
    SEVERITIES,
    load_law,
    load_lifecycle,
    load_profiles,
    load_rules,
)
from lexshield.report import REF_LABEL, WHO


def load_norms() -> dict:
    return load_law()["norm"]


def test_rule_ids_unique_and_well_formed():
    ids = [rule.id for rule in load_rules()]
    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r"LS-(SYS|ACC|DAT|NET)-\d{2}", rule_id) for rule_id in ids)


def test_short_names_unique_and_easy_to_type():
    # Lower case, no umlauts or spaces, so they work on any keyboard and in any shell.
    names = [rule.name for rule in load_rules()]
    assert len(names) == len(set(names))
    assert all(re.fullmatch(r"[a-z][a-z0-9-]{1,19}", name) for name in names), names


def test_rules_reference_known_checks_categories_severities_and_norms():
    norms = load_norms()
    for rule in load_rules():
        assert rule.check in CHECKS, rule.id
        assert rule.category in CATEGORIES, rule.id
        assert rule.severity in SEVERITIES, rule.id
        assert rule.norms and all(norm in norms for norm in rule.norms), rule.id
        assert rule.title and rule.why and rule.fix and rule.legal and rule.basis, rule.id
        assert rule.who in WHO, rule.id


def test_legal_model_is_consistent():
    law = load_law()
    assert isinstance(law["checked"], date)
    for key, norm in law["norm"].items():
        assert norm["duty"] in law["duty"], key
        assert norm["act"] in law["act"], key
        # The reference names its act, and fits the reference column of the terminal.
        assert norm["ref"].endswith(" " + law["act"][norm["act"]]["name"]), key
        assert len(norm["ref"]) < REF_LABEL, key
        assert norm["title"] and norm["text"], key
        assert norm["text"].count("«") == norm["text"].count("»"), key
    for act in law["act"].values():
        assert act["binds"] and act["url"].startswith("https://")
    assert {norm["act"] for norm in law["norm"].values()} == set(law["act"])
    for question in law["question"]:
        assert question["title"].endswith("?") and question["text"] and question["sources"]


def test_every_duty_is_checked_somewhere():
    law = load_law()
    duties = {law["norm"][key]["duty"] for rule in load_rules() for key in rule.norms}
    assert duties == set(law["duty"])


def test_every_check_and_norm_is_used():
    rules = load_rules()
    assert {rule.check for rule in rules} == set(CHECKS)
    assert {norm for rule in rules for norm in rule.norms} == set(load_norms())


def test_profile_overrides_are_valid_and_reasoned():
    rule_ids = {rule.id for rule in load_rules()}
    profiles = load_profiles()
    assert {"einzel", "klein", "mittel", "gross"} <= set(profiles)
    for profile in profiles.values():
        for item in profile.get("override", []):
            assert item["rule"] in rule_ids
            assert item["severity"] in SEVERITIES
            assert item["reason"]


def test_lifecycle_dates_are_dates_with_sources():
    lifecycle = load_lifecycle()
    assert isinstance(lifecycle["checked"], date)
    assert lifecycle["windows10"]["source"].startswith("https://learn.microsoft.com/")
    assert lifecycle["windows11"]["source"].startswith("https://learn.microsoft.com/")
    assert lifecycle["office"]["sources"]
    for build, entry in lifecycle["windows11"]["builds"].items():
        assert build.isdigit() and int(build) >= 22000
        for channel in ("home_pro", "enterprise"):
            assert channel in entry.get("ended", []) or isinstance(entry[channel], date), (build, channel)
    assert all(isinstance(end, date) for end in lifecycle["office"]["end"].values())
