"""Rule evaluation: facts + rules + profile -> report."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from datetime import date
from importlib import resources

from .checks import CHECKS, FAIL, SKIP, WARN, Context, Outcome
from .facts import normalize, reference_date

SEVERITIES = ("critical", "high", "medium", "low")
RANK = {severity: index for index, severity in enumerate(SEVERITIES)}  # 0 = most severe
CATEGORIES = {
    "system": "Systemschutz",
    "accounts": "Konten und Zugriff",
    "data": "Mandatsdaten",
    "network": "Netzwerk",
}
ASSESSMENTS = {"critical": "KRITISCH", "high": "HOCH", "medium": "MITTEL", "low": "GERING"}
VERDICT_OK = "OK"
VERDICT_INCOMPLETE = "UNVOLLSTÄNDIG"


def load_data(name: str) -> dict:
    text = resources.files("lexshield").joinpath("data", name).read_text(encoding="utf-8")
    return tomllib.loads(text)


@dataclass(frozen=True)
class Rule:
    id: str  # stable key in reports and JSON, e.g. LS-SYS-03
    name: str  # what people see and type in the terminal, e.g. virenschutz
    category: str
    check: str
    severity: str
    title: str
    why: str
    fix: str
    legal: str  # what an open finding means legally, in plain words
    basis: str
    norms: tuple[str, ...] = ()
    params: dict = field(default_factory=dict, hash=False, compare=False)
    who: str = "it"  # who usually fixes it: "selbst" (in a few minutes at the device) or "it"
    fix_it: str = ""  # the part of the fix only an IT person can do
    severity_note: str = ""  # when the check raises its own severity


def load_rules() -> list[Rule]:
    return [
        Rule(
            id=raw["id"],
            name=raw["name"],
            category=raw["category"],
            check=raw["check"],
            severity=raw["severity"],
            title=raw["title"],
            why=raw["why"],
            fix=raw["fix"],
            legal=raw["legal"],
            basis=raw["basis"],
            norms=tuple(raw.get("norms", ())),
            params=dict(raw.get("params", {})),
            who=raw.get("who", "it"),
            fix_it=raw.get("fix_it", ""),
            severity_note=raw.get("severity_note", ""),
        )
        for raw in load_data("rules.toml")["rule"]
    ]


def find_rule(rules: list[Rule], query: str) -> Rule | None:
    """Look a rule up by short name, title or id, ignoring case."""
    wanted = query.strip().casefold()
    for rule in rules:
        if wanted in (rule.name, rule.title.casefold(), rule.id.casefold()):
            return rule
    return None


def load_profiles() -> dict:
    return load_data("profiles.toml")["profile"]


def load_law() -> dict:
    """Duties, acts, norms and open questions from norms.toml."""
    return load_data("norms.toml")


def load_lifecycle() -> dict:
    return load_data("lifecycle.toml")


def profile_overrides(profile: dict) -> dict[str, str]:
    return {item["rule"]: item["severity"] for item in profile.get("override", [])}


def step_down(severity: str) -> str:
    return SEVERITIES[min(RANK[severity] + 1, len(SEVERITIES) - 1)]


@dataclass(frozen=True)
class Finding:
    rule: Rule
    status: str
    detail: str
    severity: str  # after profile override and context escalation

    @property
    def weight(self) -> str | None:
        """Severity counted in the summary. A warning counts one level lower."""
        if self.status == FAIL:
            return self.severity
        if self.status == WARN:
            return step_down(self.severity)
        return None


@dataclass
class Report:
    facts: dict
    profile_key: str
    profile: dict
    findings: list[Finding]
    ref_date: date
    ref_note: str | None = None  # set when the snapshot's own date could not be used

    def weight_counts(self) -> dict[str, int]:
        counts = {severity: 0 for severity in SEVERITIES}
        for finding in self.findings:
            if finding.weight:
                counts[finding.weight] += 1
        return counts

    def status_counts(self) -> dict[str, int]:
        counts = {"pass": 0, "warn": 0, "fail": 0, "skip": 0}
        for finding in self.findings:
            counts[finding.status] += 1
        return counts

    def issues(self) -> list[Finding]:
        """Findings that need action, most severe first; at the same level, what one can fix oneself first."""
        flagged = [f for f in self.findings if f.weight]
        return sorted(flagged, key=lambda f: (RANK[f.weight], f.rule.who != "selbst", f.status != FAIL))

    def unverified(self) -> list[Finding]:
        """Checks that could not run, most severe rule first."""
        skipped = [f for f in self.findings if f.status == SKIP]
        return sorted(skipped, key=lambda f: RANK[f.severity])

    def assessment(self) -> str:
        """The worst open finding; UNVOLLSTÄNDIG when something more severe could not be checked.

        An unchecked disk encryption must not read as "nothing open".
        """
        issues, unverified = self.issues(), self.unverified()
        worst = issues[0].weight if issues else None
        if unverified and (worst is None or RANK[unverified[0].severity] < RANK[worst]):
            return VERDICT_INCOMPLETE
        return ASSESSMENTS[worst] if worst else VERDICT_OK

    def verdict_level(self) -> str | None:
        """The severity behind the verdict, for its colour; None when everything is in order."""
        if self.assessment() == VERDICT_INCOMPLETE:
            return self.unverified()[0].severity
        issues = self.issues()
        return issues[0].weight if issues else None

    def reaches(self, threshold: str) -> bool:
        """An open finding, or a check that could not run, at or above the threshold."""
        levels = [f.weight for f in self.issues()] + [f.severity for f in self.unverified()]
        return any(RANK[level] <= RANK[threshold] for level in levels)

    def cited_norms(self) -> list[str]:
        cited: list[str] = []
        for finding in self.issues():
            for norm in finding.rule.norms:
                if norm not in cited:
                    cited.append(norm)
        return cited

    def duties(self, law: dict) -> list[tuple[str, list[Finding], list[str]]]:
        """Duties touched by open findings: (duty key, findings, norm keys), in the order of norms.toml."""
        norms = law["norm"]
        touched = []
        for duty in law["duty"]:
            findings, keys = [], []
            for finding in self.issues():
                hits = [k for k in finding.rule.norms if k in norms and norms[k]["duty"] == duty]
                if hits:
                    findings.append(finding)
                    keys += [k for k in hits if k not in keys]
            if findings:
                touched.append((duty, findings, [k for k in norms if k in keys]))
        return touched


def evaluate(
    facts: dict,
    profile_key: str = "klein",
    *,
    rules: list[Rule] | None = None,
    profiles: dict | None = None,
    lifecycle: dict | None = None,
) -> Report:
    rules = rules if rules is not None else load_rules()
    profiles = profiles if profiles is not None else load_profiles()
    if profile_key not in profiles:
        raise KeyError(f"Unbekanntes Profil: {profile_key}")
    profile = profiles[profile_key]
    overrides = profile_overrides(profile)
    facts = normalize(facts)
    ref_date, ref_note = reference_date(facts)
    ctx = Context(ref_date=ref_date, lifecycle=lifecycle or load_lifecycle())
    findings = []
    for rule in rules:
        try:
            outcome = CHECKS[rule.check](facts, rule.params, ctx)
        except Exception:  # one malformed fact must not abort the whole audit
            outcome = Outcome(SKIP, "Prüfung fehlgeschlagen: unerwartete Werte in der Erhebung")
        severity = overrides.get(rule.id, rule.severity)
        if outcome.severity and RANK[outcome.severity] < RANK[severity]:
            severity = outcome.severity
        findings.append(Finding(rule, outcome.status, outcome.detail, severity))
    return Report(facts, profile_key, profile, findings, ctx.ref_date, ref_note)
