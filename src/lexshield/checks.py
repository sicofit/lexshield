"""Check functions.

Each check interprets facts the collector recorded and returns an Outcome.
Checks never touch the system, so they run on any OS against saved facts,
which is how the test suite exercises them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import Any, Callable

PASS, WARN, FAIL, SKIP = "pass", "warn", "fail", "skip"


@dataclass(frozen=True)
class Outcome:
    status: str
    detail: str
    severity: str | None = None  # set when context raises the rule's severity


@dataclass(frozen=True)
class Context:
    ref_date: date
    lifecycle: dict


Check = Callable[[dict, dict, Context], Outcome]
CHECKS: dict[str, Check] = {}


def check(name: str) -> Callable[[Check], Check]:
    def register(fn: Check) -> Check:
        CHECKS[name] = fn
        return fn

    return register


# --------------------------------------------------------------------------- helpers


def get(facts: Any, path: str) -> Any:
    current = facts
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def as_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def as_bool(value: Any) -> bool | None:
    """True or False only for values that clearly say so; anything else counts as not read."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


def as_count(value: Any) -> int | None:
    """A non-negative whole number, or None."""
    if isinstance(value, bool):
        return None
    number = as_int(value)
    return number if number is not None and number >= 0 else None


def parse_date(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def fmt_date(value: date) -> str:
    return value.strftime("%d.%m.%Y")


def fmt_duration(seconds: int) -> str:
    if seconds >= 3600 and seconds % 3600 == 0:
        return f"{seconds // 3600} Std."
    if seconds >= 60:
        return f"{round(seconds / 60)} Min."
    return f"{seconds} s"


def days_ago(days: int) -> str:
    if days <= 0:
        return "heute"
    return "vor 1 Tag" if days == 1 else f"vor {days} Tagen"


def short_name(account: str) -> str:
    return account.split("\\")[-1]


def names(items: list[dict]) -> str:
    return ", ".join(item["name"] for item in items)


# --------------------------------------------------------------------------- Windows naming

EDITIONS = {
    "Core": "Home",
    "CoreN": "Home N",
    "CoreSingleLanguage": "Home",
    "Professional": "Pro",
    "ProfessionalN": "Pro N",
    "ProfessionalEducation": "Pro Education",
    "ProfessionalWorkstation": "Pro for Workstations",
    "Enterprise": "Enterprise",
    "EnterpriseN": "Enterprise N",
    "EnterpriseS": "Enterprise LTSC",
    "Education": "Education",
}
LTSC_EDITIONS = ("EnterpriseS", "EnterpriseSN", "IoTEnterpriseS")
WINDOWS10_22H2 = 19045
LONG_SERVICING = ("Enterprise", "Education", "IoTEnterprise")  # 36 instead of 24 months


def is_server(os_facts: dict) -> bool:
    return str(os_facts.get("edition_id") or "").startswith("Server")


def windows_name(os_facts: dict, with_build: bool = True) -> str:
    """Human name of the Windows version.

    The registry value ProductName still reads "Windows 10" on Windows 11,
    so the build number decides the family.
    """
    if not os_facts:
        return "Windows (Version unbekannt)"
    build = as_int(os_facts.get("build"))
    edition = str(os_facts.get("edition_id") or "")
    if is_server(os_facts):
        parts = [str(os_facts.get("product_name") or "Windows Server")]
    else:
        family = "Windows 11" if build and build >= 22000 else "Windows 10"
        parts = [family, EDITIONS.get(edition, edition)]
    parts.append(str(os_facts.get("display_version") or ""))
    name = " ".join(part for part in parts if part)
    ubr = as_int(os_facts.get("ubr"))
    if build and with_build:
        name += f" (Build {build}.{ubr})" if ubr is not None else f" (Build {build})"
    return name


def end_of_support(label: str, end: date, ref: date, warn_days: int) -> Outcome:
    days = (end - ref).days
    if days < 0:
        return Outcome(FAIL, f"{label}: seit {fmt_date(end)} keine Sicherheitsupdates mehr")
    if days <= warn_days:
        return Outcome(WARN, f"{label}: Sicherheitsupdates nur noch bis {fmt_date(end)} (noch {days} Tage)")
    return Outcome(PASS, f"{label}: Sicherheitsupdates bis {fmt_date(end)}")


# --------------------------------------------------------------------------- system


@check("os_lifecycle")
def os_lifecycle(facts: dict, params: dict, ctx: Context) -> Outcome:
    os_facts = facts.get("os") or {}
    build = as_int(os_facts.get("build"))
    if build is None:
        return Outcome(SKIP, "Windows-Version nicht lesbar")
    edition = str(os_facts.get("edition_id") or "")
    name = windows_name(os_facts, with_build=False)  # the header already shows the build
    if is_server(os_facts):
        return Outcome(SKIP, f"{name}: Windows Server prüft LexShield nicht")
    if edition in LTSC_EDITIONS:
        return Outcome(SKIP, f"{name}: LTSC-Ausgaben prüft LexShield nicht")
    warn_days = int(params.get("warn_days", 90))
    lifecycle = ctx.lifecycle
    if build < 22000:
        if build < WINDOWS10_22H2:  # older versions ended earlier, and ESU covers only 22H2
            return Outcome(FAIL, f"{name}: keine Sicherheitsupdates mehr (Version vor 22H2)")
        end = lifecycle["windows10"]["end"]
        outcome = end_of_support(name, end, ctx.ref_date, warn_days)
        if outcome.status != FAIL:
            return outcome
        latest = esu_update(facts, end, ctx.ref_date)
        if latest:
            return Outcome(
                WARN, f"{name}: Sicherheitsupdates nur noch über Extended Security Updates (ESU), "
                f"zuletzt am {fmt_date(latest)}",
            )
        return Outcome(FAIL, outcome.detail + " (Extended Security Updates nicht erkannt)")
    builds = lifecycle["windows11"]["builds"]
    entry = builds.get(str(build))
    if entry is None:
        if build > max(int(known) for known in builds):
            checked = fmt_date(lifecycle["checked"])
            return Outcome(PASS, f"{name}: neuer als alle bekannten Versionen (Stand {checked})")
        return Outcome(SKIP, f"{name}: Version unbekannt (Vorabversion?)")
    channel = "enterprise" if edition.startswith(LONG_SERVICING) else "home_pro"
    if channel in entry.get("ended", []):
        return Outcome(FAIL, f"{name}: keine Sicherheitsupdates mehr")
    return end_of_support(name, entry[channel], ctx.ref_date, warn_days)


# Updates that are not the monthly Windows update: malicious software removal tool,
# Defender signatures and platform, Windows Security platform.
NON_OS_KB = {"KB890830", "KB2267602", "KB4052623", "KB5007651", "KB915597"}
NON_OS_WORDS = ("defender", "security intelligence", "sicherheitsinformation", "antimalware", ".net")
OS_UPDATE_WORDS = (
    "cumulative update",
    "kumulatives update",
    "mise à jour cumulative",
    "aggiornamento cumulativo",
    "security update",
    "sicherheitsupdate",
)
BUILD_MARK = re.compile(r"\(\d{5}\.\d+\)")  # "(26200.9711)" in titles since Windows 11 24H2


def is_os_update(entry: dict) -> bool:
    kb = str(entry.get("kb") or "").upper()
    title = str(entry.get("title") or "").lower()
    if kb in NON_OS_KB or any(word in title for word in NON_OS_WORDS):
        return False
    if BUILD_MARK.search(title):
        return True
    return "windows" in title and any(word in title for word in OS_UPDATE_WORDS)


def os_update_dates(facts: dict) -> list[date]:
    """Dates of installed Windows updates from the update history."""
    history = get(facts, "updates.history")
    history = history if isinstance(history, list) else []
    found = [parse_date(e.get("date")) for e in history if isinstance(e, dict) and is_os_update(e)]
    return [d for d in found if d]


RELEASE_MONTH = re.compile(r"^\s*(\d{4})-(\d{2})\b")  # "2025-11 Sicherheitsupdate für Windows 10 …"
ESU_GRACE_DAYS = 35  # an update released before the end may still be installed a cycle later


def esu_update(facts: dict, end: date, ref_date: date) -> date | None:
    """When the last Windows update released after the end of support was installed, if any.

    Such an update can only have come through Extended Security Updates. The release month
    stands at the start of the title; without it, only an update installed well after the end counts.
    """
    history = get(facts, "updates.history")
    found = []
    for entry in history if isinstance(history, list) else []:
        if not isinstance(entry, dict) or not is_os_update(entry):
            continue
        installed = parse_date(entry.get("date"))
        if not installed or installed > ref_date:
            continue
        month = RELEASE_MONTH.match(str(entry.get("title") or ""))
        if month and 1 <= int(month.group(2)) <= 12:
            if (int(month.group(1)), int(month.group(2))) > (end.year, end.month):
                found.append(installed)
        elif (installed - end).days > ESU_GRACE_DAYS:
            found.append(installed)
    return max(found, default=None)


@check("update_age")
def update_age(facts: dict, params: dict, ctx: Context) -> Outcome:
    found = os_update_dates(facts)
    source = ""
    if not found:
        hotfix = parse_date(get(facts, "updates.latest_hotfix"))
        if hotfix:
            found, source = [hotfix], " (laut Hotfix-Liste)"
    dates = [d for d in found if d <= ctx.ref_date]  # a date after the collection cannot be right
    if not dates:
        if found:
            return Outcome(SKIP, "Update-Datum liegt nach dem Erhebungsdatum")
        return Outcome(SKIP, "Update-Verlauf nicht lesbar")
    last = max(dates)
    age = (ctx.ref_date - last).days
    detail = f"Letztes Update am {fmt_date(last)}, {days_ago(age)}{source}"
    if age > int(params["fail_days"]):
        return Outcome(FAIL, detail)
    if age > int(params["warn_days"]):
        return Outcome(WARN, detail)
    return Outcome(PASS, detail)


WSC_STATES = {0: "off", 1: "on", 2: "snoozed", 3: "expired"}
STATE_DE = {"on": "aktiv", "off": "aus", "snoozed": "pausiert", "expired": "abgelaufen", "unknown": "unbekannt"}


def decode_wsc_state(value: int) -> dict:
    """Decode productState from root/SecurityCenter2.

    Microsoft does not document this bit field. LexShield uses the decoding in
    wide use and cross-checked it against the documented IWscProduct interface
    (tools/wsc_crosscheck.py).
    """
    return {
        "state": WSC_STATES.get((value >> 12) & 0xF, "unknown"),
        "signatures_current": ((value >> 4) & 0xF) == 0,
        "microsoft": ((value >> 8) & 0xF) == 1,
    }


def security_products(facts: dict, path: str) -> list[dict]:
    products = []
    listed = get(facts, path)
    for product in listed if isinstance(listed, list) else []:
        if not isinstance(product, dict):
            continue
        state = as_int(product.get("product_state"))
        if state is None or not 0 <= state <= 0xFFFFFF:  # outside the documented 24-bit field
            continue
        products.append({
            "name": str(product.get("name") or "Unbekannt"),
            # False when the product's program file is gone: an entry left behind by an uninstall
            "present": as_bool(product.get("exe_present")),
            **decode_wsc_state(state),
        })
    return products


def installed_products(facts: dict, path: str) -> tuple[list[dict], list[dict]]:
    """Security products that are still installed, and the entries left behind by uninstalled ones."""
    products = security_products(facts, path)
    return [p for p in products if p["present"] is not False], [p for p in products if p["present"] is False]


@check("antivirus")
def antivirus(facts: dict, params: dict, ctx: Context) -> Outcome:
    products, orphans = installed_products(facts, "antivirus.products")
    realtime = as_bool(get(facts, "defender.realtime"))
    active = [p for p in products if p["state"] == "on"]
    if active:
        return Outcome(PASS, f"{names(active)}: eingeschaltet")
    if realtime is True:
        return Outcome(PASS, "Microsoft Defender: eingeschaltet")
    paused = [p for p in products if p["state"] == "snoozed"]
    if paused:
        return Outcome(WARN, f"{names(paused)}: pausiert (laut Windows-Sicherheit)")
    left = f"; {names(orphans)} ist deinstalliert, nur sein Eintrag blieb" if orphans else ""
    if products:
        listed = ", ".join(f"{p['name']} {STATE_DE[p['state']]}" for p in products)
        return Outcome(FAIL, f"Kein Virenschutz eingeschaltet ({listed}){left}")
    if realtime is False:
        return Outcome(FAIL, f"Microsoft Defender: ausgeschaltet{left}")
    return Outcome(SKIP, "Virenschutz nicht lesbar")


@check("av_signatures")
def av_signatures(facts: dict, params: dict, ctx: Context) -> Outcome:
    max_age = int(params["max_age_days"])
    products = [p for p in installed_products(facts, "antivirus.products")[0] if p["state"] in ("on", "snoozed")]
    third_party = [p for p in products if not p["microsoft"]]
    stale = [p for p in third_party if not p["signatures_current"]]
    if stale:
        return Outcome(FAIL, f"{names(stale)}: veraltet (laut Windows-Sicherheit)")
    age = as_int(get(facts, "defender.signature_age_days"))
    realtime = as_bool(get(facts, "defender.realtime"))
    # A switched-off Defender keeps updating its signatures; they say nothing about protection then.
    defender_in_use = realtime is True or (
        realtime is None and not third_party and as_bool(get(facts, "defender.service_enabled")) is True
    )
    if defender_in_use and age is not None:
        if age == 65535:  # Defender's value when no signatures are loaded at all
            return Outcome(FAIL, "Microsoft Defender: keine Virensignaturen geladen")
        if age < 0:
            return Outcome(SKIP, f"Alter der Virensignaturen nicht plausibel ({age} Tage)")
        updated = "heute aktualisiert" if age == 0 else f"zuletzt aktualisiert {days_ago(age)}"
        return Outcome(FAIL if age > max_age else PASS, f"Microsoft Defender: {updated}")
    if defender_in_use and not third_party:
        return Outcome(SKIP, "Alter der Virensignaturen nicht lesbar")
    if third_party:
        return Outcome(PASS, f"{names(third_party)}: aktuell (laut Windows-Sicherheit)")
    return Outcome(SKIP, "Kein Virenschutz eingeschaltet, siehe Punkt Virenschutz")


# The network names Windows shows in the app "Windows-Sicherheit".
PROFILE_DE = {"Domain": "Domänennetzwerk", "Private": "privates Netzwerk", "Public": "öffentliches Netzwerk"}


@check("firewall")
def firewall(facts: dict, params: dict, ctx: Context) -> Outcome:
    profiles = get(facts, "firewall.profiles")
    third_party = [
        p for p in security_products(facts, "firewall.products") if p["state"] == "on" and not p["microsoft"]
    ]
    if not isinstance(profiles, dict) or not profiles:
        if third_party:
            return Outcome(PASS, f"{names(third_party)}: eingeschaltet")
        return Outcome(SKIP, "Firewall nicht lesbar")
    states = {PROFILE_DE.get(name, name): as_bool(value) for name, value in profiles.items()}
    off = [name for name, on in states.items() if on is False]
    unread = [name for name, on in states.items() if on is None]
    if off:
        if third_party:
            return Outcome(PASS, f"{names(third_party)}: eingeschaltet (Windows-Firewall aus für {', '.join(off)})")
        return Outcome(FAIL, f"Windows-Firewall aus für {', '.join(off)}")
    # Switched on but letting every incoming connection through protects nothing.
    inbound = get(facts, "firewall.inbound")
    allowed = [
        PROFILE_DE.get(name, name) for name, action in (inbound.items() if isinstance(inbound, dict) else [])
        if str(action).strip().lower() == "allow"
    ]
    if allowed and not third_party:
        return Outcome(FAIL, f"Windows-Firewall lässt alle eingehenden Verbindungen zu ({', '.join(allowed)})")
    if unread and not third_party:
        return Outcome(SKIP, f"Windows-Firewall für {', '.join(unread)} nicht lesbar")
    extra = f", zusätzlich {names(third_party)}" if third_party else ""
    return Outcome(PASS, f"Windows-Firewall eingeschaltet{extra}")


@check("secure_boot")
def secure_boot(facts: dict, params: dict, ctx: Context) -> Outcome:
    value = as_int(facts.get("secure_boot"))
    if value == 1:
        # Windows reports the switch to the certificates of 2023; older Windows has no such value.
        status = facts.get("secure_boot_ca2023")
        if isinstance(status, str) and status.strip() and status.strip().lower() != "updated":
            return Outcome(WARN, f"Secure Boot ist eingeschaltet, die neuen Zertifikate von 2023 fehlen (Status «{status}»)")
        return Outcome(PASS, "Secure Boot ist eingeschaltet")
    if value == 0:
        return Outcome(FAIL, "Secure Boot ist ausgeschaltet")
    return Outcome(SKIP, "Secure Boot nicht lesbar (älteres Gerät?)")


@check("smb1")
def smb1(facts: dict, params: dict, ctx: Context) -> Outcome:
    smb = facts.get("smb1")
    if not isinstance(smb, dict):
        return Outcome(SKIP, "SMB-Einstellungen nicht lesbar")
    server = as_bool(smb.get("server_enabled"))
    if server is None and as_int(smb.get("server_registry")) is not None:
        server = as_int(smb.get("server_registry")) == 1
    client_present = as_bool(smb.get("client_driver_present"))
    client = client_present is True and as_int(smb.get("client_driver_start")) != 4
    found = []
    if server:
        found.append("Server eingeschaltet")
    if client:
        found.append("Client installiert")
    if found:
        return Outcome(FAIL, f"SMBv1 noch vorhanden: {', '.join(found)}")
    if server is None and client_present is None:
        return Outcome(SKIP, "SMB-Einstellungen nicht lesbar")
    if server is None:
        return Outcome(PASS, "SMBv1-Client entfernt (Serverteil nicht lesbar)")
    if client_present is None:
        return Outcome(PASS, "SMBv1-Server ausgeschaltet (Clientteil nicht lesbar)")
    return Outcome(PASS, "SMBv1 ist entfernt")


OFFICE_YEAR = re.compile(r"(2016|2019|2021|2024)")
INSTALLED_YEAR = re.compile(r"\b(2007|2010|2013|2016|2019|2021|2024)\b")
# Click-to-Run product IDs without a year belong to the Office 2016 generation.
C2R_2016 = {
    "ProPlusRetail", "ProPlusVolume", "StandardRetail", "StandardVolume", "HomeBusinessRetail",
    "HomeStudentRetail", "ProfessionalRetail", "PersonalRetail", "VisioProRetail", "VisioStdRetail",
    "ProjectProRetail", "ProjectStdRetail",
}


def office_generations(office: dict) -> dict[str, str]:
    """Map Office generation ("365", "2019", ...) to a display label."""
    found: dict[str, str] = {}
    for product in office.get("c2r_products") or []:
        product = str(product)
        if "365" in product:
            found.setdefault("365", "Microsoft 365 Apps")
        elif match := OFFICE_YEAR.search(product):
            found.setdefault(match.group(1), f"Office {match.group(1)}")
        elif product in C2R_2016:
            found.setdefault("2016", "Office 2016")
    for name in office.get("installed") or []:
        name = str(name)
        if "365" in name:
            found.setdefault("365", "Microsoft 365 Apps")
        elif match := INSTALLED_YEAR.search(name):
            found.setdefault(match.group(1), f"Office {match.group(1)}")
    return found


STATUS_RANK = {FAIL: 0, WARN: 1, PASS: 2}  # worst first; severities rank in engine.RANK


@check("office_lifecycle")
def office_lifecycle(facts: dict, params: dict, ctx: Context) -> Outcome:
    office = facts.get("office")
    if not isinstance(office, dict):
        return Outcome(SKIP, "Office nicht lesbar")
    generations = office_generations(office)
    if not generations:  # nothing installed is nothing outdated
        return Outcome(PASS, "Kein Microsoft Office gefunden")
    ends = ctx.lifecycle["office"]["end"]
    warn_days = int(params.get("warn_days", 90))
    # Click-to-Run installations update themselves unless that is switched off.
    click_to_run = office_generations({"c2r_products": office.get("c2r_products")})
    updates = as_bool(office.get("updates_enabled"))
    version = office.get("version")
    version = f" (Version {version})" if isinstance(version, str) and version.strip() else ""
    outcomes = []
    for generation, label in sorted(generations.items()):
        if generation in click_to_run and updates is False:
            outcomes.append(Outcome(FAIL, f"{label}: automatische Updates ausgeschaltet{version}"))
        elif generation == "365":
            detail = "automatische Updates eingeschaltet" if updates else "erhält laufend Updates"
            outcomes.append(Outcome(PASS, f"{label}: {detail}{version}"))
        elif generation in ends:
            outcomes.append(end_of_support(label, ends[generation], ctx.ref_date, warn_days))
        else:
            outcomes.append(Outcome(FAIL, f"{label}: seit Jahren keine Sicherheitsupdates mehr"))
    worst = min(outcomes, key=lambda o: STATUS_RANK[o.status]).status
    return Outcome(worst, "; ".join(o.detail for o in sorted(outcomes, key=lambda o: STATUS_RANK[o.status])))


OFFICE_APPS = ("Word", "Excel", "PowerPoint")


@check("office_macros")
def office_macros(facts: dict, params: dict, ctx: Context) -> Outcome:
    office = facts.get("office")
    if not isinstance(office, dict):
        return Outcome(SKIP, "Office-Einstellungen nicht lesbar")
    if not office_generations(office):
        return Outcome(PASS, "Kein Microsoft Office gefunden")
    macros = office.get("macros")
    if "macros" in office and not isinstance(macros, dict):  # the collector could not read them
        return Outcome(SKIP, "Makroeinstellungen nicht lesbar")
    macros = macros if isinstance(macros, dict) else {}
    allowed, blocked = [], []
    for app in OFFICE_APPS:
        settings = macros.get(app)
        settings = settings if isinstance(settings, dict) else {}
        effective = as_int(settings.get("policy_vba_warnings"))
        if effective is None:
            effective = as_int(settings.get("vba_warnings"))
        if effective == 1:  # 1 = enable all macros
            allowed.append(app)
        if as_int(settings.get("policy_block_internet")) == 1:
            blocked.append(app)
    if allowed:
        return Outcome(FAIL, f"{', '.join(allowed)}: alle Makros laufen ohne Rückfrage")
    if len(blocked) == len(OFFICE_APPS):
        return Outcome(PASS, "Makros nur nach Rückfrage, Makros aus dem Internet gesperrt")
    return Outcome(PASS, "Makros nur nach Rückfrage (Office-Standard)")


# --------------------------------------------------------------------------- accounts


@check("daily_admin")
def daily_admin(facts: dict, params: dict, ctx: Context) -> Outcome:
    value = as_bool(get(facts, "accounts.current_user_admin"))
    # Started under a separate administrator account, the collector judges the person at the device.
    session = get(facts, "host.session_user") if as_bool(get(facts, "host.other_user")) else None
    account = f"Das angemeldete Konto {short_name(str(session))}" if session else "Das angemeldete Konto"
    if value is None:
        if session:
            return Outcome(SKIP, f"Rechte des angemeldeten Kontos {short_name(str(session))} nicht eindeutig "
                                 "(Mitglied über eine Gruppe?)")
        return Outcome(SKIP, "Kontorechte nicht lesbar")
    if value:
        return Outcome(FAIL, f"{account} hat Administratorrechte")
    return Outcome(PASS, f"{account} ist ein Standardkonto")


# A member shown only by its SID could not be resolved to a name: on Entra-joined devices,
# the roles "Global Administrator" and "Device Administrator".
SID_NAME = re.compile(r"(^|\\)S-1-\d+(-\d+)+$")


@check("admin_count")
def admin_count(facts: dict, params: dict, ctx: Context) -> Outcome:
    admins = get(facts, "accounts.admins")
    if not isinstance(admins, list):
        return Outcome(SKIP, "Mitglieder der Gruppe Administratoren nicht lesbar")
    admins = [a for a in admins if isinstance(a, dict)]
    if not admins:  # the group always holds at least the built-in Administrator
        return Outcome(SKIP, "Mitglieder der Gruppe Administratoren nicht lesbar")
    # Groups and roles are not accounts: they are shown, not counted.
    groups = [a for a in admins if as_bool(a.get("group")) or SID_NAME.search(str(a.get("name") or ""))]
    accounts = [a for a in admins if a not in groups]
    enabled = [a for a in accounts if a.get("enabled") is not False]
    disabled = len(accounts) - len(enabled)
    count = "1 aktives Administratorkonto" if len(enabled) == 1 else f"{len(enabled)} aktive Administratorkonten"
    detail = count
    if enabled:
        detail += ": " + ", ".join(short_name(str(a.get("name") or "?")) for a in enabled)
    if disabled:
        detail += f" ({disabled} deaktiviert)"
    if groups:
        detail += f"; dazu {len(groups)} {'Gruppe oder Rolle' if len(groups) == 1 else 'Gruppen oder Rollen'}: "
        detail += ", ".join(short_name(str(a.get("name") or "?")) for a in groups)
    return Outcome(FAIL if len(enabled) > int(params["max_enabled"]) else PASS, detail)


@check("guest_account")
def guest_account(facts: dict, params: dict, ctx: Context) -> Outcome:
    value = as_bool(get(facts, "accounts.guest_enabled"))
    if value is None:
        return Outcome(SKIP, "Gastkonto nicht lesbar")
    return Outcome(FAIL, "Gastkonto ist aktiv") if value else Outcome(PASS, "Gastkonto ist deaktiviert")


@check("uac")
def uac(facts: dict, params: dict, ctx: Context) -> Outcome:
    lua = as_int(get(facts, "uac.enable_lua"))
    consent = as_int(get(facts, "uac.consent_prompt_admin"))
    if lua is None:
        return Outcome(SKIP, "Benutzerkontensteuerung nicht lesbar")
    if lua == 0:
        return Outcome(FAIL, "Benutzerkontensteuerung ist ausgeschaltet")
    if consent == 0:
        return Outcome(FAIL, "Programme erhalten Administratorrechte ohne Rückfrage")
    return Outcome(PASS, "Benutzerkontensteuerung ist eingeschaltet")


@check("rdp")
def rdp(facts: dict, params: dict, ctx: Context) -> Outcome:
    settings = facts.get("rdp")
    if not isinstance(settings, dict):
        return Outcome(SKIP, "Remotedesktop-Einstellungen nicht lesbar")
    deny = as_int(settings.get("policy_deny_connections"))
    if deny is None:
        deny = as_int(settings.get("deny_connections"))
    if deny is None:
        return Outcome(SKIP, "Remotedesktop-Einstellungen nicht lesbar")
    if deny == 1:
        return Outcome(PASS, "Remotedesktop ist ausgeschaltet")
    nla = as_int(settings.get("policy_nla"))
    if nla is None:
        nla = as_int(settings.get("nla"))
    if nla == 1:
        return Outcome(PASS, "Remotedesktop eingeschaltet, mit Anmeldung vor dem Verbindungsaufbau (NLA)")
    return Outcome(FAIL, "Remotedesktop eingeschaltet, ohne Anmeldung vor dem Verbindungsaufbau (NLA)")


NEVER = 86_400  # a delay of a day or more means the device does not lock on its own


def power_locks(lock: dict, power: str) -> list[tuple[int, str]]:
    """How the power settings lock the device on mains ("ac") or battery ("dc"): seconds and source.

    Sleep, and on Modern Standby devices switching the screen off, lock only when Windows asks for
    the sign-in on wake-up (power setting CONSOLELOCK = 1).
    """
    if as_int(get(lock, f"wake_lock.{power}")) != 1:
        return []
    found = []
    sleep = as_count(get(lock, f"sleep_s.{power}"))
    if sleep:
        found.append((sleep, "Energiesparmodus"))
    off = as_count(get(lock, f"screen_off_s.{power}"))
    delay = as_count(lock.get("delay_lock_s")) or 0
    if as_bool(lock.get("modern_standby")) is True and off and delay < NEVER:
        found.append((off + delay, "Bildschirm aus"))
    return found


@check("screen_lock")
def screen_lock(facts: dict, params: dict, ctx: Context) -> Outcome:
    lock = facts.get("lock")
    if not isinstance(lock, dict):
        return Outcome(SKIP, "Sperreinstellungen nicht lesbar")
    candidates: list[tuple[int, str]] = []
    policy = as_count(lock.get("policy_inactivity_s"))
    if policy:
        candidates.append((policy, "Richtlinie"))
    for key in ("screensaver_policy", "screensaver"):
        saver = lock.get(key)
        if isinstance(saver, dict) and as_bool(saver.get("exe_set")) is True and as_int(saver.get("active")) == 1 \
                and as_int(saver.get("secure")) == 1:
            timeout = as_count(saver.get("timeout_s"))
            if timeout:
                candidates.append((timeout, "Bildschirmschoner mit Anmeldung"))
    limit = int(params["max_seconds"])
    on_mains = candidates + power_locks(lock, "ac")
    if not on_mains:
        sleep_ac, off_ac = as_count(get(lock, "sleep_s.ac")), as_count(get(lock, "screen_off_s.ac"))
        standby = as_bool(lock.get("modern_standby")) is True
        sleeps = bool(sleep_ac) or (standby and bool(off_ac))
        wake = as_int(get(lock, "wake_lock.ac"))
        if sleeps and wake is None:
            return Outcome(SKIP, "Nicht lesbar, ob Windows nach dem Energiesparmodus die Anmeldung verlangt")
        if not sleeps and sleep_ac is None:  # "never" is 0; None means powercfg could not be read
            return Outcome(SKIP, "Energiesparmodus nicht lesbar")
        if sleeps:  # wake == 0
            detail = "Am Strom angeschlossen verlangt Windows nach dem Energiesparmodus keine Anmeldung"
        else:
            detail = "Am Strom angeschlossen sperrt sich das Gerät nie von selbst"
        on_battery = candidates + power_locks(lock, "dc")
        if on_battery:
            detail += f", im Akkubetrieb nach {fmt_duration(min(on_battery)[0])}"
        return Outcome(FAIL, detail)
    seconds, source = min(on_mains)
    if seconds > limit:
        detail = f"Sperrt erst nach {fmt_duration(seconds)} ({source}), empfohlen höchstens {fmt_duration(limit)}"
        return Outcome(WARN, detail)
    return Outcome(PASS, f"Sperrt nach {fmt_duration(seconds)} ({source})")


# --------------------------------------------------------------------------- client data


def local_documents(facts: dict) -> tuple[int, int] | None:
    docs = facts.get("local_docs")
    if not isinstance(docs, dict):
        return None
    total = old = 0
    seen = False
    for folder in ("desktop", "downloads"):
        entry = docs.get(folder)
        if entry is None:  # the folder does not exist on this device
            continue
        if not isinstance(entry, dict):
            return None
        count, aged = as_count(entry.get("documents")), as_count(entry.get("older_than_30_days"))
        if count is None or aged is None or aged > count:  # a count that cannot be right is not a count
            return None
        seen = True
        total += count
        old += aged
    return (total, old) if seen else None


# Shell property System.Volume.BitLockerProtection. Only the unambiguous values
# are mapped; everything else needs the BitLocker module, which requires admin rights.
BITLOCKER_SHELL = {1: "on", 2: "off", 3: "encrypting"}


def drive_state(entry: dict) -> tuple[str | None, bool]:
    """BitLocker state of one drive, and whether it came from the Explorer instead of BitLocker itself."""
    status = str(entry.get("protection_status") or "").strip().lower()
    if status in ("on", "off"):  # the BitLocker module, with administrator rights
        volume = str(entry.get("volume_status") or "").strip().lower()
        if status == "on":
            return "on", False
        if volume == "fullyencrypted":  # encrypted, but the key lies unprotected on the disk
            return "suspended", False
        if volume in ("encryptioninprogress", "encryptionpaused"):
            return "encrypting", False
        return "off", False
    raw = as_int(entry.get("shell_value"))
    return (BITLOCKER_SHELL.get(raw) if raw is not None else None), True


def drive_list(drives: list[str], one: str, many: str) -> str:
    return f"Laufwerk {drives[0]} {one}" if len(drives) == 1 else f"Laufwerke {', '.join(drives)} {many}"


@check("bitlocker")
def bitlocker(facts: dict, params: dict, ctx: Context) -> Outcome:
    listed = get(facts, "bitlocker.drives")
    drives = [d for d in listed if isinstance(d, dict) and d.get("drive")] if isinstance(listed, list) else []
    if not drives:
        return Outcome(SKIP, "BitLocker-Status nicht lesbar")
    states: dict[str, list[str]] = {}
    explorer = False
    for entry in drives:
        state, via_explorer = drive_state(entry)
        states.setdefault(state or "unclear", []).append(str(entry["drive"]))
        explorer = explorer or (via_explorer and state is not None)
    unclear = states.get("unclear", [])
    note = f"; {drive_list(unclear, 'unklar', 'unklar')}" if unclear else ""
    if "off" in states:
        off = states["off"]
        system = next((str(d["drive"]) for d in drives if as_bool(d.get("system"))), None)
        docs = local_documents(facts)
        detail = drive_list(off, "ist nicht verschlüsselt", "sind nicht verschlüsselt")
        if system in off and docs and docs[0] > 0:
            # The documents in Downloads and on the desktop lie on the system drive.
            return Outcome(
                FAIL, f"{detail}. Allein in Downloads und auf dem Desktop liegen {docs[0]} Dokumente{note}",
                severity="critical",
            )
        return Outcome(FAIL, detail + note)
    if "suspended" in states:
        return Outcome(WARN, drive_list(states["suspended"], "ist verschlüsselt, der Schutz aber angehalten",
                                        "sind verschlüsselt, der Schutz aber angehalten") + note)
    if "encrypting" in states:
        return Outcome(WARN, drive_list(states["encrypting"], "wird noch verschlüsselt", "werden noch verschlüsselt")
                       + note)
    if unclear:
        return Outcome(SKIP, f"BitLocker-Status von {', '.join(unclear)} unklar; als Administrator starten")
    source = " (laut Windows-Explorer; als Administrator genauer)" if explorer else ""
    return Outcome(PASS, drive_list(states["on"], "ist", "sind") + f" mit BitLocker verschlüsselt{source}")


@check("removable_media")
def removable_media(facts: dict, params: dict, ctx: Context) -> Outcome:
    settings = facts.get("removable")
    if not isinstance(settings, dict):
        return Outcome(SKIP, "Richtlinien für USB-Sticks nicht lesbar")
    if as_int(settings.get("deny_all")) == 1 or as_int(settings.get("deny_write_disks")) == 1:
        return Outcome(PASS, "Schreiben auf USB-Sticks ist gesperrt")
    if as_int(settings.get("bitlocker_required_for_write")) == 1:
        return Outcome(PASS, "Nur verschlüsselte USB-Sticks sind beschreibbar")
    # Programs of other makers can enforce this too; LexShield sees only the Windows policies.
    return Outcome(FAIL, "Keine Windows-Richtlinie gefunden, die unverschlüsselte USB-Sticks sperrt")


@check("local_documents")
def local_documents_check(facts: dict, params: dict, ctx: Context) -> Outcome:
    docs = local_documents(facts)
    if docs is None:
        return Outcome(SKIP, "Ordner Downloads und Desktop nicht lesbar")
    total, old = docs
    detail = f"{total} Dokumente, davon {old} älter als 30 Tage"
    return Outcome(WARN if total > int(params["max_documents"]) else PASS, detail)


# --------------------------------------------------------------------------- network


@check("llmnr")
def llmnr(facts: dict, params: dict, ctx: Context) -> Outcome:
    if not isinstance(facts.get("network"), dict):
        return Outcome(SKIP, "Netzwerkeinstellungen nicht lesbar")
    if as_int(get(facts, "network.llmnr_policy")) == 0:
        return Outcome(PASS, "LLMNR ist per Richtlinie ausgeschaltet")
    return Outcome(FAIL, "LLMNR ist eingeschaltet (Windows-Standard)")
