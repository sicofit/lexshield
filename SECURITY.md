# Security policy

LexShield promises two things: it only reads, and it sends nothing anywhere. A way to break
either promise is a vulnerability, and so is a way to make it report a device as safer than
it is.

## In scope

- The collector or the Python code changing a setting, writing a file other than the ones
  named on the command line, or starting a program other than PowerShell, `powercfg` and
  `whoami`.
- A way past the read-only test in `tests/test_readonly.py`: code that writes, deletes,
  executes or opens a network connection without the test failing.
- Data leaving the device, or a snapshot or report containing file names, file content or
  more account data than the README describes.
- Crafted facts (a snapshot or registry values) that crash LexShield, inject terminal
  escape sequences or Markdown, or turn an open gap into *OK*.

## Out of scope

- The state of the device being audited. LexShield reports it; it does not defend it.
- Disagreement with a severity, threshold or legal assessment. Please open an ordinary issue
  for those.

## Reporting

Please report privately through GitHub: on the repository page, open **Security** and then
**Report a vulnerability**. Do not open a public issue, and do not include real snapshots or
reports from a law firm; a synthetic snapshot that shows the problem is enough.

There is no bug bounty.

## Supported versions

Only the latest release receives fixes.
