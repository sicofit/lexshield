# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## 0.1.0 – unreleased

First release.

### Checks

- 19 read-only checks of a Windows 10 or 11 device in four areas: system protection,
  accounts and access, client data, network.
- Windows 10 with Extended Security Updates is a warning, not a failure; Microsoft 365 is
  checked for automatic updates.
- Antivirus: Defender or a third party, ignoring entries of uninstalled products.
- Firewall: all profiles on and unsolicited inbound connections blocked, or a third-party
  firewall.
- Secure Boot, including the switch to the certificates of 2023.
- Screen lock on mains and on battery, including Modern Standby, and only where Windows
  asks for sign-in on wake.
- Disk encryption of every fixed drive, with suspended protection as a warning.
- When LexShield runs as another account, for example an administrator, the user settings
  (screen lock, macros, document folders) and the daily-admin check refer to the signed-in
  user, not to the account running LexShield.

### Output

- German terminal output for people without IT training: urgency marks, the overall verdict
  as what to do and how soon, who can fix each point (*selbst* or *IT-Betreuung*), a line
  *Für IT* where needed, and the to-do list last.
- Legal framework in five duties with the norms of BGFA, SSR, StGB, DSG, DSV and OR, cited
  to the letter, and five open legal questions with sources (`lexshield law`).
- Markdown and JSON reports; `--brief`, `--verbose`, firm profiles, `--fail-on` exit codes.
- `--no-color` on every command, output fitted to the terminal width, references and
  numbers never broken across lines, and console code pages handled when output is piped.

### Safety

- The read-only promise is enforced by a test that parses the collector's syntax tree
  against allowlists and checks itself against known bypasses.
- No network connection of its own; no file names in snapshots or reports.
