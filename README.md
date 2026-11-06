# LexShield

A read-only Windows security audit for Swiss law firms, run from the terminal.

Most security scanners report what is technically wrong. LexShield also says why it matters
in a law firm: client files sit on the device, so a missing disk encryption is not just a
misconfiguration but a professional-secrecy problem. Each finding comes with the risk for
the firm, a concrete fix, who can carry it out, the source of its threshold, what it means
legally in plain words, and the Swiss norms it touches, cited to the letter (BGFA, SSR,
StGB, DSG, DSV, OR).

```text
> lexshield scan --facts examples/kanzlei-riskant.json --brief

  LEXSHIELD  Sicherheitscheck für Anwaltskanzleien                                    v0.1.0

  Gerät       KANZLEI-PC-03
  System      Windows 10 Pro 22H2 (Build 19045.6456)
  Profil      Kleine Kanzlei (2–10 Mitarbeitende)
  Geprüft     05.11.2026 09:12


  SYSTEMSCHUTZ                                                      8 offen, 1 nicht prüfbar

  KRITISCH    Windows-Version                                                   IT-Betreuung
              Windows 10 Pro 22H2: seit 14.10.2025 keine Sicherheitsupdates mehr (Extended
              Security Updates nicht erkannt)

              Warum    Ohne Sicherheitsupdates bleiben neu entdeckte Lücken offen. Angreifer
                       suchen gezielt nach solchen Geräten, etwa um Akten zu verschlüsseln
                       und Lösegeld zu fordern (Ransomware).
              Was tun  Auf die aktuelle Version von Windows 11 wechseln. Ältere Geräte
                       müssen dafür oft ersetzt werden; die IT-Betreuung weiss, ob das nötig
                       ist.
              Für IT   Windows 10 bis zum Wechsel über Extended Security Updates (ESU)
                       weiter mit Sicherheitsupdates versorgen.
              Recht    Die Datenschutzverordnung verlangt ausdrücklich, Betriebssysteme
                       «stets auf dem neusten Sicherheitsstand» zu halten. Ein Windows ohne
                       Sicherheitsupdates erfüllt das nicht mehr.

  [18 more points and the legal summary omitted here]

  ERGEBNIS

  Gesamt      KRITISCH  4 Punkte sofort beheben
  Punkte      19 geprüft: 18 offen, 1 nicht prüfbar
  Umfang      Nur dieses Gerät. Andere Kanzlei-Geräte, Datensicherung, E-Mail und Cloud
              prüft LexShield nicht.

  Nicht prüfbar
  –           Virenschutz-Updates                                        virenschutz-updates

  Zu tun, das Dringendste zuerst
  KRITISCH    Virenschutz                                  selbst        virenschutz
  KRITISCH    Windows-Version                              IT-Betreuung  windows
  KRITISCH    Office-Version                               IT-Betreuung  office
  KRITISCH    Festplattenverschlüsselung                   IT-Betreuung  festplatte
  HOCH        Windows-Updates                              selbst        updates
  HOCH        Firewall                                     selbst        firewall
  [12 more lines omitted here]

  Mehr dazu   lexshield explain virenschutz

  LexShield liest nur Einstellungen und ändert nichts. Kein Ersatz für eine Prüfung durch
  Fachleute und keine Rechtsberatung.
```

The output is in German because the audience is Swiss law firms, and it is written for
people without IT training. The example device is synthetic (see [examples/](examples/)).

## Quick start

Requires Windows 10 or 11 and Python 3.11 or later. No third-party dependencies.

```powershell
git clone https://github.com/sicofit/lexshield.git
cd lexshield
py -m venv .venv
.venv\Scripts\activate
pip install .
lexshield scan                      # audit this device
lexshield scan --profile einzel     # solo practice; also klein, mittel, gross
lexshield scan --md bericht.md      # plus a Markdown report for the firm
```

BitLocker details need administrator rights. Run the prompt as administrator to check them;
without, LexShield reads what Windows shows every user and names what it could not check.

No Windows at hand? Every command works on saved snapshots (on Debian and Ubuntu, install
`python3-venv` first):

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install .
lexshield scan --facts examples/kanzlei-riskant.json
lexshield scan --facts examples/kanzlei-solide.json
```

## Reading the result

- **Gesamt** is the most urgent open point, phrased as what to do: *KRITISCH*, fix now;
  *HOCH*, within days; *MITTEL*, no urgent gap, fix when convenient; *GERING*, only small
  things. *OK* means everything was checked and nothing is open. *UNVOLLSTÄNDIG* means a
  check that could not run weighs more than every open point, so a gap in LexShield's view
  never turns into a reassuring verdict.
- **The mark** in front of each point is its urgency. In a colour terminal, critical is
  white on red, high red, medium orange and low yellow. A warning counts one level lower
  than a failure.
- **Who** can usually fix it: *selbst* means the person at the device, in a few minutes and
  without IT knowledge; *IT-Betreuung* means the firm's IT provider. Where a fix has a part
  only IT can do, a line *Für IT* says what it is.
- **Zu tun** comes last, so it stays on screen: most urgent first, and at the same urgency
  what one can do oneself first.

## What it checks

| Name | Check | Severity | Who |
| --- | --- | --- | --- |
| `windows` | Windows version still receives security updates; Windows 10 with Extended Security Updates is a warning | critical | IT |
| `updates` | Last Windows update within 35 days (warning after that, failure after 65) | high | selbst |
| `virenschutz` | Antivirus real-time protection on, Defender or a third party; entries left behind by uninstalled products do not count | critical | selbst |
| `virenschutz-updates` | Antivirus signatures at most 7 days old | high | selbst |
| `firewall` | Windows Firewall on in all profiles and blocking unsolicited inbound connections, or a third-party firewall on | high | selbst |
| `secure-boot` | Secure Boot on; a warning while the 2023 certificates are missing, since those of 2011 expire in 2026 | medium | IT |
| `smb1` | SMBv1 removed | high | IT |
| `office` | Office version still receives security updates; Microsoft 365 with automatic updates on | critical | IT |
| `makros` | Macros not enabled across the board | high | selbst |
| `admin-alltag` | The signed-in account works without administrator rights | medium | IT |
| `admin-anzahl` | At most two active local administrators; nested groups and roles are named, not counted | medium | IT |
| `gastkonto` | Guest account disabled | medium | IT |
| `kontensteuerung` | User Account Control on and prompting | high | selbst |
| `remotedesktop` | Remote Desktop off, or on with Network Level Authentication | high | IT |
| `bildschirmsperre` | Screen locks after 15 minutes at most, on mains and on battery; sleep and Modern Standby count only if Windows asks for sign-in on wake | medium | selbst |
| `festplatte` | Every fixed drive encrypted with BitLocker and protection not suspended; critical if documents lie in Downloads or on the Desktop | high | IT |
| `usb` | USB drives writable only when encrypted | medium | selbst |
| `downloads` | At most 100 documents in Downloads and on the Desktop | low | selbst |
| `llmnr` | LLMNR disabled | low | IT |

The terminal shows the short German names, which are what people type:
`lexshield rules` lists them, `lexshield explain festplatte` shows one in full. The JSON and
Markdown reports also carry stable IDs (`LS-SYS-01` and so on).

## What the snapshot contains

`lexshield scan --save-facts FILE` and `lexshield collect -o FILE` write the collected
settings as JSON. The snapshot names the device and Windows accounts: the computer name,
the signed-in user, local accounts and the members of the local Administrators group, which
on a domain device include domain accounts. It also lists installed antivirus products, the
Office version and how many documents lie in Downloads and on the Desktop. It never contains
a file name or file content, because file names in a law firm often contain client names.

Treat a snapshot like an internal document. The `.gitignore` keeps `reports/` and the
default file names out of version control.

## Design

**Read-only, and the tests enforce it.** [`tests/test_readonly.py`](tests/test_readonly.py)
parses the PowerShell collector into its syntax tree and fails if a command, parameter,
method, type, COM object or external program is not on an allowlist. The collector may run
only `powercfg` (`/qh`, `/query`, `/a`) and `whoami /groups`, both by their full path in
System32, and may create only the COM objects `Shell.Application` and
`Microsoft.Update.Session`. The test also plants known ways around such a check (aliases,
`Invoke-Expression`, commands built from strings, .NET calls, dynamic member names, writing
COM methods, remote CIM queries, redirection) and makes sure each one is caught. On the
Python side, it allows only listed imports and calls: no network modules, no shell,
`subprocess` only to start PowerShell with the bundled collector, `ctypes` only for the
console.

**No network connection of its own.** LexShield sends nothing anywhere. On a domain device,
Windows may ask the domain controller to resolve account names, and if Downloads or the
Desktop is redirected to a server, counting the documents there reads over the network.

**Facts, then rules.** Collection and evaluation are separate steps. The rule engine is a
pure function of the snapshot, evaluated against its collection date. The same snapshot
always gives the same report, which makes all 19 checks testable on any OS. It also lets
someone collect on the firm's device and evaluate elsewhere.

**Rules as data.** Texts, severities, thresholds and who fixes what live in
[`rules.toml`](src/lexshield/data/rules.toml); the logic lives in
[`checks.py`](src/lexshield/checks.py). Every rule names the basis of its threshold: an
external source (CIS Benchmark, CIS Controls, Microsoft, the guide of the Federal Data
Protection and Information Commissioner, FDPIC) or, where none exists, the explicit label
*LexShield-Konvention*.

**Sourced dates.** End-of-support dates for Windows and Office sit in
[`lifecycle.toml`](src/lexshield/data/lifecycle.toml), each checked against the cited
Microsoft page. Updating them means editing data, not code.

**Context changes severity.** An unencrypted disk is *high*; an unencrypted system drive
with client documents in Downloads or on the Desktop is *critical*. Firm profiles (solo,
small, medium, large) adjust severities too, each override with a stated reason
(`lexshield profiles`).

**Honest about uncertainty.** A check that cannot decide says so, with the reason, instead
of guessing (shown as a dash). A value the collector could not read, or one of an
unexpected type, never decides a check either way. Without administrator rights,
BitLocker is read through the Windows shell, and only its unambiguous values count. The
antivirus state comes from an undocumented WMI field;
[`tools/wsc_crosscheck.py`](tools/wsc_crosscheck.py) compares that decoding with the
documented Windows Security Center API, and on the development machine the two matched.

## Legal framework

The law is organised as five duties a firm owes. Every norm belongs to one duty, every
check cites the norms it serves, and every output follows the same order: duty, then norm,
then finding.

| Duty | In plain words | Norms |
| --- | --- | --- |
| Berufsgeheimnis | What clients confide must not reach anyone unauthorised. | Art. 13 Abs. 1 BGFA, Art. 321 Ziff. 1 StGB |
| Hilfspersonen | Whoever reaches client data for the firm, such as an IT provider, is chosen with care and bound to secrecy; the firm answers for harm they cause clients as for its own. | Art. 13 Abs. 2 BGFA, Art. 38 SSR, Art. 9 DSG, Art. 101 Abs. 1 OR |
| Datensicherheit | Client data is protected according to the state of the art. | Art. 37 SSR, Art. 8 Abs. 1 DSG, Art. 1 Abs. 4 DSV, Art. 3 DSV (eight letters) |
| Sorgfalt und Haftung | Serious gaps can breach professional diligence and found liability under the mandate. | Art. 12 lit. a BGFA, Art. 398 Abs. 2 OR |
| Meldepflicht | Only once something has happened: a breach is documented, and reported to the FDPIC if it likely means a high risk for those affected. | Art. 24 DSG, Art. 15 Abs. 4 DSV |

Where it shows up:

- **Each open finding** has a line *Recht*: what it means legally, in one or two plain
  sentences.
- **The summary** lists the duties the open findings touch, which findings touch them and
  the articles involved. Where the Swiss Rules of Professional Conduct (SSR) are cited, it
  notes that they bind only members of the Swiss Bar Association.
- **`lexshield explain NAME`**, `scan --verbose` and the reports give the exact references,
  down to the letter; `explain` also quotes their wording.
- **`lexshield law`** prints the whole framework: each duty with its norms and the checks
  that test them, who is bound by which act, with links to the official texts, and five
  open legal questions with their sources.

All of it lives in [`norms.toml`](src/lexshield/data/norms.toml). Text in «» is the
verbatim wording, checked against the official sources on the date in the file; everything
else is a summary. Where the law is unsettled, LexShield says so instead of choosing a side:

- **Does an IT gap make one punishable?** Art. 321 StGB requires intent, and the offence is
  complete only once a third party actually learns the secret.
- **Is an IT or cloud provider an auxiliary?** The prevailing view says yes, a minority
  says no. Either way, Art. 62 Abs. 2 DSG punishes anyone who intentionally discloses
  secret personal data learned while working for the firm.
- **Does the fine in Art. 61 lit. c DSG apply?** Disputed in the literature, so no finding
  cites it.
- **May client data go to a US cloud?** Recognised for data protection since 15 September
  2024 for certified companies; open for professional secrecy because of the US CLOUD Act.
- **Does a report to the FDPIC breach professional secrecy?** The report needs no names,
  but reports are official documents, so it should not reveal a mandate.

LexShield is not legal advice and does not replace an assessment by security professionals.

## Commands and exit codes

| Command | Purpose |
| --- | --- |
| `lexshield scan` | collect and evaluate; `--facts`, `--save-facts`, `--json`, `--md`, `--brief`, `--verbose`, `--profile`, `--fail-on` |
| `lexshield collect -o FILE` | collect only |
| `lexshield explain NAME` | one check with risk, fix, who, legal meaning, basis and norms (name, title or ID) |
| `lexshield law` | the legal framework: duties, norms, who is bound, open questions |
| `lexshield rules` / `profiles` | list the checks / the firm profiles |

Every command except `collect` takes `--no-color`; the environment variable `NO_COLOR`
works too. Output follows the terminal width, up to 92 columns.

Exit code 0: nothing at or above `--fail-on` (default `high`). 1: at least one open finding,
or one check that could not run, at or above it. 2: error, such as an unreadable snapshot or
an output path that does not exist; LexShield checks output paths before it starts.

Snapshots are read as UTF-8 (with or without BOM), UTF-16 (what `>` writes in Windows
PowerShell 5.1) or ANSI. Output piped into another program uses the console's code page, as
Windows' own tools do; set `PYTHONIOENCODING=utf-8` to get UTF-8 instead.

## Limits of version 0.1

- One device per run. No Microsoft 365, backup, network or server checks yet.
- Not yet checked: automatic sign-in, remote-maintenance tools such as TeamViewer or
  AnyDesk, and the account lockout policy.
- The screen-lock check does not detect Dynamic Lock.

## Roadmap

- **0.2:** Microsoft 365 (MFA, external sharing, stale accounts) via read-only Graph scopes;
  backup presence and recency; the checks listed under limits.
- **0.3:** Reports across several devices; known vulnerabilities (NVD/CVE) for installed
  software.

## Development

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m pytest                              # offline tests
$env:LEXSHIELD_LIVE = "1"; .venv\Scripts\python -m pytest   # plus the real collector
```

See [CHANGELOG.md](CHANGELOG.md) for changes and [SECURITY.md](SECURITY.md) for reporting a
vulnerability. Licensed under the [MIT License](LICENSE).
