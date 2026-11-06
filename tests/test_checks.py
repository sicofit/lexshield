"""Single checks against small hand-made facts."""

import pytest

from lexshield.checks import (
    CHECKS,
    FAIL,
    PASS,
    SKIP,
    WARN,
    decode_wsc_state,
    fmt_duration,
    is_os_update,
    office_generations,
    windows_name,
)


def run(name, facts, ctx, **params):
    return CHECKS[name](facts, params, ctx)


# --------------------------------------------------------------------------- decoding


@pytest.mark.parametrize(
    ("value", "state", "current", "microsoft"),
    [
        (397568, "on", True, True),  # 0x61100 Defender on
        (393472, "off", True, True),  # 0x60100 Defender off
        (270336, "snoozed", True, False),  # 0x42000 third party paused
        (266240, "on", True, False),  # 0x41000 third party on
        (397584, "on", False, True),  # 0x61110 Defender on, signatures out of date
    ],
)
def test_decode_wsc_state(value, state, current, microsoft):
    decoded = decode_wsc_state(value)
    assert decoded == {"state": state, "signatures_current": current, "microsoft": microsoft}


def test_windows_name_ignores_misleading_product_name():
    # The registry says "Windows 10 Pro" on every Windows 11 machine.
    os_facts = {"product_name": "Windows 10 Pro", "edition_id": "Professional", "display_version": "25H2",
                "build": 26200, "ubr": 9711}
    assert windows_name(os_facts) == "Windows 11 Pro 25H2 (Build 26200.9711)"


@pytest.mark.parametrize(("seconds", "text"), [(30, "30 s"), (600, "10 Min."), (10800, "3 Std.")])
def test_fmt_duration(seconds, text):
    assert fmt_duration(seconds) == text


# --------------------------------------------------------------------------- lifecycle


def os_facts(build, edition="Professional", version=""):
    return {"os": {"build": build, "edition_id": edition, "display_version": version}}


@pytest.mark.parametrize(
    ("build", "edition", "status"),
    [
        (19045, "Professional", FAIL),  # Windows 10 ended 14.10.2025
        (22631, "Professional", FAIL),  # 23H2 Home/Pro ended 11.11.2025
        (22631, "Enterprise", WARN),  # 23H2 Enterprise ends 10.11.2026, in 5 days
        (26100, "Professional", FAIL),  # 24H2 Home/Pro ended 13.10.2026
        (26100, "Enterprise", PASS),  # 24H2 Enterprise until 12.10.2027
        (26100, "ProfessionalEducation", FAIL),  # Pro Education follows Home/Pro
        (26200, "Professional", PASS),  # 25H2
        (22000, "Enterprise", FAIL),  # 21H2 ended for all
        (29000, "Professional", PASS),  # newer than every known build
        (26120, "Professional", SKIP),  # unknown build between known ones
        (26100, "EnterpriseS", SKIP),  # LTSC has its own lifecycle
        (26100, "ServerStandard", SKIP),
    ],
)
def test_os_lifecycle(build, edition, status, ctx):
    assert run("os_lifecycle", os_facts(build, edition), ctx, warn_days=90).status == status


def test_windows10_mentions_esu(ctx):
    outcome = run("os_lifecycle", os_facts(19045), ctx, warn_days=90)
    assert "Extended Security Updates nicht erkannt" in outcome.detail


def update(installed, title):
    return {"date": installed, "kb": "KB5000001", "title": title}


@pytest.mark.parametrize(
    ("history", "status"),
    [
        # Released after the end of support: only ESU delivers that.
        ([update("2026-10-16", "2026-10 Sicherheitsupdate für Windows 10 Version 22H2 (KB5000001)")], WARN),
        # The last free update, installed a day after the end: no ESU.
        ([update("2025-10-15", "2025-10 Kumulatives Update für Windows 10 Version 22H2 (KB5000001)")], FAIL),
        # Without a release month in the title, only an update installed well after the end counts.
        ([update("2025-11-05", "Sicherheitsupdate für Windows (KB5000001)")], FAIL),
        ([update("2026-01-20", "Sicherheitsupdate für Windows (KB5000001)")], WARN),
        # Defender signatures are no Windows update.
        ([update("2026-11-01", "Security Intelligence-Update für Microsoft Defender Antivirus - KB2267602")], FAIL),
    ],
)
def test_windows10_with_esu_is_a_warning(history, status, ctx):
    facts = {**os_facts(19045), "updates": {"history": history}}
    assert run("os_lifecycle", facts, ctx, warn_days=90).status == status


def test_windows10_before_22h2_has_no_esu(ctx):
    facts = {**os_facts(19044), "updates": {"history": [update("2026-10-16", "2026-10 Sicherheitsupdate für Windows 10")]}}
    outcome = run("os_lifecycle", facts, ctx, warn_days=90)
    assert outcome.status == FAIL and outcome.detail.endswith("(Version vor 22H2)")


@pytest.mark.parametrize(
    ("office", "status"),
    [
        ({"c2r_products": ["O365ProPlusRetail", "OneNoteFreeRetail"]}, PASS),
        ({"c2r_products": ["ProPlus2019Retail"]}, FAIL),
        ({"c2r_products": ["HomeBusiness2021Retail"]}, FAIL),  # ended 13.10.2026
        ({"c2r_products": ["HomeBusiness2024Retail"]}, PASS),
        ({"c2r_products": ["ProPlusRetail"]}, FAIL),  # no year = Office 2016
        ({"installed": ["Microsoft Office Professional Plus 2013"]}, FAIL),
        ({"c2r_products": ["O365BusinessRetail", "ProPlus2019Retail"]}, FAIL),  # worst wins
        ({"c2r_products": ["OneNoteFreeRetail"]}, PASS),  # no Office installed: nothing outdated
        ({"c2r_products": [], "installed": []}, PASS),
    ],
)
def test_office_lifecycle(office, status, ctx):
    assert run("office_lifecycle", {"office": office}, ctx, warn_days=90).status == status


def test_office_generations_deduplicate_c2r_and_uninstall_entries():
    office = {"c2r_products": ["HomeBusiness2019Retail"], "installed": ["Microsoft Office Home and Business 2019 - de-de"]}
    assert office_generations(office) == {"2019": "Office 2019"}


# --------------------------------------------------------------------------- updates


@pytest.mark.parametrize(
    ("title", "kb", "expected"),
    [
        ("2026-10 Sicherheitsupdate (KB5127648) (26200.9711)", "KB5127648", True),
        ("2025-09 Kumulatives Update für Windows 10 Version 22H2 für x64-basierte Systeme (KB5000001)", "KB5000001", True),
        ("2025-09 Cumulative Update for Windows 11 Version 23H2 for x64-based Systems (KB5000002)", "KB5000002", True),
        ("2026-10 .NET Framework Sicherheitsupdate (KB5127690)", "KB5127690", False),
        ("Windows-Tool zum Entfernen bösartiger Software x64 - v5.146 (KB890830)", "KB890830", False),
        ("Security Intelligence-Update für Microsoft Defender Antivirus - KB2267602", "KB2267602", False),
        ("Update für Windows Security platform - KB5007651 (Version 10.0.29680.1000)", "KB5007651", False),
    ],
)
def test_is_os_update(title, kb, expected):
    assert is_os_update({"title": title, "kb": kb}) is expected


@pytest.mark.parametrize(("last", "status"), [("2026-10-15", PASS), ("2026-09-20", WARN), ("2026-07-01", FAIL)])
def test_update_age(last, status, ctx):
    facts = {"updates": {"history": [{"date": last, "kb": "KB5000001", "title": "2026 Sicherheitsupdate (26200.1)"}]}}
    assert run("update_age", facts, ctx, warn_days=35, fail_days=65).status == status


def test_update_age_falls_back_to_hotfix_list(ctx):
    outcome = run("update_age", {"updates": {"history": [], "latest_hotfix": "2026-10-20"}}, ctx,
                  warn_days=35, fail_days=65)
    assert outcome.status == PASS and "Hotfix" in outcome.detail


# --------------------------------------------------------------------------- antivirus and firewall


def av(*states, defender=None):
    facts = {"antivirus": {"products": [{"name": f"AV{i}", "product_state": s} for i, s in enumerate(states)]}}
    if defender is not None:
        facts["defender"] = defender
    return facts


def test_antivirus_paused_third_party_is_a_warning(ctx):
    outcome = run("antivirus", av(393472, 270336), ctx)
    assert outcome.status == WARN and "pausiert" in outcome.detail


def test_antivirus_any_active_product_passes(ctx):
    assert run("antivirus", av(393472, 266240), ctx).status == PASS


def test_antivirus_all_off_fails(ctx):
    assert run("antivirus", av(393472), ctx).status == FAIL


def test_antivirus_defender_realtime_passes_without_security_center(ctx):
    assert run("antivirus", {"defender": {"realtime": True}}, ctx).status == PASS


def test_signatures_of_defender_judged_by_age(ctx):
    facts = av(397568, defender={"realtime": True, "service_enabled": True, "signature_age_days": 9})
    assert run("av_signatures", facts, ctx, max_age_days=7).status == FAIL


def test_firewall_off_but_third_party_on_passes(ctx):
    facts = {"firewall": {"profiles": {"Public": "False"}, "products": [{"name": "FW", "product_state": 266240}]}}
    assert run("firewall", facts, ctx).status == PASS


def test_firewall_profile_off_fails(ctx):
    outcome = run("firewall", {"firewall": {"profiles": {"Domain": "True", "Public": "False"}}}, ctx)
    assert outcome.status == FAIL and "öffentliches Netzwerk" in outcome.detail


# --------------------------------------------------------------------------- data


def disks(*drives):
    """BitLocker facts: C: is the system drive, further drives follow."""
    return {"bitlocker": {"drives": [
        {"drive": "CDEF"[i] + ":", "system": i == 0, **drive} for i, drive in enumerate(drives)
    ]}}


def test_bitlocker_off_with_local_documents_escalates_to_critical(ctx):
    facts = {**disks({"shell_value": 2}), "local_docs": {"downloads": {"documents": 5, "older_than_30_days": 0}}}
    outcome = run("bitlocker", facts, ctx)
    assert outcome.status == FAIL and outcome.severity == "critical"


def test_bitlocker_off_without_documents_keeps_rule_severity(ctx):
    outcome = run("bitlocker", disks({"shell_value": 2}), ctx)
    assert outcome.status == FAIL and outcome.severity is None


def test_bitlocker_ambiguous_shell_value_is_skipped(ctx):
    assert run("bitlocker", disks({"shell_value": 8}), ctx).status == SKIP
    assert run("bitlocker", {"bitlocker": {"drives": []}}, ctx).status == SKIP


def test_bitlocker_module_status_wins_over_shell(ctx):
    assert run("bitlocker", disks({"shell_value": 1, "protection_status": "Off"}), ctx).status == FAIL


def test_bitlocker_checks_every_fixed_drive(ctx):
    outcome = run("bitlocker", disks({"shell_value": 1}, {"shell_value": 2}), ctx)
    assert outcome.status == FAIL and outcome.detail == "Laufwerk D: ist nicht verschlüsselt"
    # Documents lie on the system drive; an unencrypted data drive does not make them critical.
    facts = {**disks({"shell_value": 1}, {"shell_value": 2}),
             "local_docs": {"downloads": {"documents": 5, "older_than_30_days": 0}}}
    assert run("bitlocker", facts, ctx).severity is None
    outcome = run("bitlocker", disks({"shell_value": 1}, {"shell_value": 1}), ctx)
    assert outcome.status == PASS and outcome.detail.startswith("Laufwerke C:, D: sind mit BitLocker")


def test_bitlocker_suspended_protection_is_a_warning(ctx):
    facts = disks({"shell_value": 1, "protection_status": "Off", "volume_status": "FullyEncrypted"})
    outcome = run("bitlocker", facts, ctx)
    assert outcome.status == WARN and "angehalten" in outcome.detail


# --------------------------------------------------------------------------- accounts


WAKE = {"ac": 1, "dc": 1}  # power setting CONSOLELOCK: sign-in required on wake-up


@pytest.mark.parametrize(
    ("lock", "status"),
    [
        ({"policy_inactivity_s": 600}, PASS),
        ({"policy_inactivity_s": 1800}, WARN),
        ({"screensaver": {"exe_set": True, "active": "1", "secure": "1", "timeout_s": "300"}}, PASS),
        ({"screensaver": {"exe_set": True, "active": "1", "secure": "0", "timeout_s": "300"}}, SKIP),
        ({"screensaver": {"exe_set": True, "active": "1", "secure": "0"}, "sleep_s": {"ac": 0}}, FAIL),
        ({"sleep_s": {"ac": 0, "dc": 180}, "wake_lock": WAKE}, FAIL),
        ({"sleep_s": {"ac": None, "dc": None}, "policy_inactivity_s": None}, SKIP),  # powercfg failed
        ({"sleep_s": {"ac": -5}}, SKIP),
        ({"sleep_s": {"ac": 900, "dc": 180}, "wake_lock": WAKE}, PASS),
        # Sleep locks only when Windows asks for the sign-in on wake-up.
        ({"sleep_s": {"ac": 900}, "wake_lock": {"ac": 0, "dc": 0}}, FAIL),
        ({"sleep_s": {"ac": 900}}, SKIP),
        # Modern Standby: switching the screen off is standby, plus the delay before the sign-in.
        ({"sleep_s": {"ac": 0}, "screen_off_s": {"ac": 600}, "modern_standby": True, "wake_lock": WAKE}, PASS),
        ({"sleep_s": {"ac": 0}, "screen_off_s": {"ac": 600}, "modern_standby": True, "wake_lock": WAKE,
          "delay_lock_s": 900}, WARN),
        ({"sleep_s": {"ac": 0}, "screen_off_s": {"ac": 10800}, "modern_standby": True, "wake_lock": WAKE}, WARN),
        ({"sleep_s": {"ac": 0}, "screen_off_s": {"ac": 600}, "modern_standby": False, "wake_lock": WAKE}, FAIL),
        ({"sleep_s": {"ac": 0}, "screen_off_s": {"ac": 600}, "modern_standby": True, "wake_lock": WAKE,
          "delay_lock_s": 4294967295}, FAIL),  # "never"
    ],
)
def test_screen_lock(lock, status, ctx):
    assert run("screen_lock", {"lock": lock}, ctx, max_seconds=900).status == status


def test_screen_lock_says_what_happens_on_battery(ctx):
    lock = {"sleep_s": {"ac": 0, "dc": 180}, "wake_lock": {"ac": 1, "dc": 1}}
    detail = run("screen_lock", {"lock": lock}, ctx, max_seconds=900).detail
    assert detail == "Am Strom angeschlossen sperrt sich das Gerät nie von selbst, im Akkubetrieb nach 3 Min."


def test_admin_count_ignores_disabled_accounts(ctx):
    admins = [{"name": "PC\\Administrator", "enabled": False}, {"name": "PC\\a", "enabled": True},
              {"name": "PC\\b", "enabled": None}]
    outcome = run("admin_count", {"accounts": {"admins": admins}}, ctx, max_enabled=2)
    assert outcome.status == PASS
    assert outcome.detail == "2 aktive Administratorkonten: a, b (1 deaktiviert)"


def test_rdp_policy_overrides_local_setting(ctx):
    facts = {"rdp": {"deny_connections": 0, "policy_deny_connections": 1}}
    assert run("rdp", facts, ctx).status == PASS


def test_uac_prompt_disabled_fails(ctx):
    assert run("uac", {"uac": {"enable_lua": 1, "consent_prompt_admin": 0}}, ctx).status == FAIL


# --------------------------------------------------------------------------- values that were not read


@pytest.mark.parametrize(
    ("name", "facts", "status"),
    [
        # A value the collector could not read, or one in the wrong type, never decides a check.
        ("daily_admin", {"accounts": {"current_user_admin": "false"}}, PASS),
        ("daily_admin", {"accounts": {"current_user_admin": "ja"}}, SKIP),
        ("guest_account", {"accounts": {"guest_enabled": "false"}}, PASS),
        ("guest_account", {"accounts": {"guest_enabled": 1}}, SKIP),
        ("antivirus", {"defender": {"realtime": "false"}}, FAIL),
        ("antivirus", {"defender": {"realtime": None, "service_enabled": True}}, SKIP),
        ("antivirus", av(-1), SKIP),  # productState outside its 24-bit field
        ("firewall", {"firewall": {"profiles": {"Domain": "True", "Private": "True", "Public": None}}}, SKIP),
        ("firewall", {"firewall": {"profiles": {"Domain": "True", "Private": "True", "Public": 0}}}, SKIP),
        ("firewall", {"firewall": {"profiles": {"Domain": "True", "Private": "False", "Public": None}}}, FAIL),
        ("smb1", {"smb1": {}}, SKIP),
        ("admin_count", {"accounts": {"admins": []}}, SKIP),
        ("local_documents", {"local_docs": {"desktop": {"documents": "viele", "older_than_30_days": 3}}}, SKIP),
        ("local_documents", {"local_docs": {"desktop": {"documents": -500, "older_than_30_days": 0}}}, SKIP),
        ("local_documents", {"local_docs": {"desktop": {"documents": 3, "older_than_30_days": 435}}}, SKIP),
        ("local_documents", {"local_docs": {"desktop": None, "downloads": {"documents": 4, "older_than_30_days": 1}}}, PASS),
        ("update_age", {"updates": {"latest_hotfix": "2027-03-01"}}, SKIP),  # after the collection date
    ],
)
def test_unread_values_are_unverified_not_decisive(name, facts, status, ctx):
    params = {"max_enabled": 2, "max_documents": 100, "fail_days": 65, "warn_days": 35}
    assert run(name, facts, ctx, **params).status == status


def test_defender_without_signatures_fails(ctx):
    facts = {"defender": {"realtime": True, "service_enabled": True, "signature_age_days": 65535}}
    outcome = run("av_signatures", facts, ctx, max_age_days=7)
    assert outcome.status == FAIL and "keine Virensignaturen" in outcome.detail


def test_negative_signature_age_is_not_today(ctx):
    facts = {"defender": {"realtime": True, "service_enabled": True, "signature_age_days": -3}}
    assert run("av_signatures", facts, ctx, max_age_days=7).status == SKIP


def test_unreadable_document_count_does_not_lower_the_disk_rating(ctx):
    facts = {**disks({"shell_value": 2}), "local_docs": {"desktop": {"documents": "viele", "older_than_30_days": 0}}}
    outcome = run("bitlocker", facts, ctx)
    assert outcome.status == FAIL and outcome.severity is None and "Dokumente" not in outcome.detail


# --------------------------------------------------------------------------- package D: what the security review found


def test_uninstalled_antivirus_does_not_count_as_protection(ctx):
    facts = {
        "antivirus": {"products": [{"name": "OldAV", "product_state": 266240, "exe_present": False}]},
        "defender": {"realtime": False},
    }
    outcome = run("antivirus", facts, ctx)
    assert outcome.status == FAIL and "OldAV ist deinstalliert" in outcome.detail


def test_switched_off_defender_has_no_signature_verdict(ctx):
    facts = {"defender": {"realtime": False, "service_enabled": True, "signature_age_days": 0}}
    assert run("av_signatures", facts, ctx, max_age_days=7).status == SKIP


def test_firewall_that_lets_everything_in_fails(ctx):
    facts = {"firewall": {"profiles": {"Domain": "True", "Private": "True", "Public": "True"},
                          "inbound": {"Domain": "Block", "Private": "Allow", "Public": "Block"}, "products": []}}
    outcome = run("firewall", facts, ctx)
    assert outcome.status == FAIL and "privates Netzwerk" in outcome.detail


@pytest.mark.parametrize(("status", "expected"), [("Updated", PASS), ("NotStarted", WARN), (None, PASS)])
def test_secure_boot_certificates_of_2023(status, expected, ctx):
    assert run("secure_boot", {"secure_boot": 1, "secure_boot_ca2023": status}, ctx).status == expected


def test_office_with_updates_switched_off_fails(ctx):
    office = {"c2r_products": ["O365ProPlusRetail"], "updates_enabled": "False", "version": "16.0.1"}
    outcome = run("office_lifecycle", {"office": office}, ctx, warn_days=90)
    assert outcome.status == FAIL and "Version 16.0.1" in outcome.detail
    office["updates_enabled"] = "True"
    assert run("office_lifecycle", {"office": office}, ctx, warn_days=90).status == PASS


def test_unreadable_macro_settings_are_unverified(ctx):
    office = {"c2r_products": ["O365ProPlusRetail"], "macros": None}
    assert run("office_macros", {"office": office}, ctx).status == SKIP


def test_groups_and_roles_are_shown_not_counted(ctx):
    admins = [
        {"name": "PC\\Administrator", "sid": "S-1-5-21-1-2-3-500", "group": False, "enabled": False},
        {"name": "AzureAD\\AnnaMuster", "sid": "S-1-12-1-1-2-3-4", "group": False, "enabled": None},
        {"name": "S-1-12-1-11-22-33-44", "sid": "S-1-12-1-11-22-33-44", "group": False, "enabled": None},
        {"name": "S-1-12-1-55-66-77-88", "sid": "S-1-12-1-55-66-77-88", "group": False, "enabled": None},
        {"name": "KANZLEI\\Domänen-Admins", "sid": "S-1-5-21-9-9-9-512", "group": True, "enabled": None},
    ]
    outcome = run("admin_count", {"accounts": {"admins": admins}}, ctx, max_enabled=2)
    assert outcome.status == PASS
    assert outcome.detail.startswith("1 aktives Administratorkonto: AnnaMuster (1 deaktiviert); dazu 3 Gruppen")


def test_daily_admin_judges_the_person_at_the_device(ctx):
    host = {"other_user": True, "session_user": "PC\\anna"}
    outcome = run("daily_admin", {"host": host, "accounts": {"current_user_admin": False}}, ctx)
    assert outcome.status == PASS and "anna" in outcome.detail
    outcome = run("daily_admin", {"host": host, "accounts": {"current_user_admin": None}}, ctx)
    assert outcome.status == SKIP and "anna" in outcome.detail


def test_llmnr_on_is_a_failure_so_profiles_can_weigh_it(ctx):
    assert run("llmnr", {"network": {"llmnr_policy": None}}, ctx).status == FAIL


def test_usb_names_what_was_looked_for(ctx):
    detail = run("removable_media", {"removable": {}}, ctx).detail
    assert detail == "Keine Windows-Richtlinie gefunden, die unverschlüsselte USB-Sticks sperrt"
