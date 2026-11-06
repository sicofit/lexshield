"""LexShield promises to read, never to change. These tests hold it to that.

The collector is checked from its PowerShell syntax tree, not from its text, so aliases,
abbreviated parameters, computed command names and .NET calls cannot slip past a pattern.
Everything the script runs, calls, names or writes must be on an allowlist, and each entry was
reviewed as read-only. The Python side is checked the same way with the ast module.

The bypass tests at the end plant known ways around the old text checks into a copy of the
script or into Python source and expect each one to be caught.
"""

from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
from functools import cache
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "lexshield"
SCRIPT = SRC / "collect.ps1"
INVENTORY = Path(__file__).with_name("ps_inventory.ps1")
POWERSHELL = shutil.which("powershell.exe") or shutil.which("pwsh")
needs_powershell = pytest.mark.skipif(POWERSHELL is None, reason="the PowerShell parser needs PowerShell")

# --------------------------------------------------------------------------- PowerShell allowlists

COMMANDS = {
    name.casefold()
    for name in (
        # reading
        "Get-ItemProperty", "Get-ChildItem", "Get-CimInstance", "Get-MpComputerStatus", "Get-NetFirewallProfile",
        "Get-BitLockerVolume", "Get-HotFix", "Get-LocalUser", "Get-LocalGroupMember", "Get-SmbServerConfiguration",
        "Get-Culture", "Get-Date", "Test-Path",
        # in memory only
        "New-Object", "Where-Object", "Sort-Object", "Select-Object", "ForEach-Object", "ConvertTo-Json",
        "Write-Output",
        # the collector's own helpers, themselves checked here
        "Get-Safe", "Get-RegValue", "Get-PowerSetting", "Test-ModernStandby",
    )
}
# Every parameter any command gets, written out in full: "-com" or "-Comp" would be abbreviations.
PARAMETERS = {
    p.casefold()
    for p in (
        "-ClassName", "-Namespace", "-Filter", "-Path", "-Name", "-Group", "-Property", "-Descending", "-First",
        "-Depth", "-Compress", "-ComObject", "-TypeName", "-ArgumentList", "-File", "-Recurse", "-Force",
        "-ErrorAction", "-MountPoint", "-SID", "-Block", "-SubGroup", "-Setting", "-Directory",
        "-ExpandProperty", "-LiteralPath", "-PolicyStore",
    )
}
# Native programs, called by their full path in System32 so that nothing earlier in PATH answers,
# each with the only first arguments it may get: /qh and /query read power settings, /a lists
# the sleep states; /change, /setacvalueindex and the like would write.
PROGRAMS = {
    '"$env:SystemRoot\\System32\\powercfg.exe"': {"/qh", "/query", "/a"},
    '"$env:SystemRoot\\System32\\whoami.exe"': {"/groups"},
}
COM_OBJECTS = {"Shell.Application", "Microsoft.Update.Session"}
NEW_TYPES = {
    "System.Text.UTF8Encoding", "System.Collections.Generic.List[string]", "Security.Principal.SecurityIdentifier",
    "Security.Principal.NTAccount",
}
# Methods that only read, whatever object they are called on.
METHODS = {
    "AddDays", "Contains", "ContainsKey", "CreateUpdateSearcher", "ExtendedProperty", "GetTotalHistoryCount",
    "GetType", "GetValue", "IsInRole", "NameSpace", "QueryHistory", "Split", "ToLowerInvariant", "ToString",
    "Translate", "Trim",
}
# Methods that can write on some objects: allowed only where the script uses them.
GUARDED_METHODS = {
    "Add": lambda m: m["target"] == "$errors",  # the script's own error list, never an ADSI group
    "Replace": lambda m: m["target"].startswith("$path"),  # strings; FileInfo.Replace would move files
    "Invoke": lambda m: m["target"] == "$group" and m["args"] == ["Members"],  # ADSI: list members only
    "InvokeMember": lambda m: m["args"][1:2] == ["GetProperty"],  # read a property, never call a method
}
STATIC_METHODS = {
    ("Convert", "ToInt64"), ("Environment", "ExpandEnvironmentVariables"), ("Math", "Min"),
    ("Security.Principal.WindowsIdentity", "GetCurrent"),
}
TYPES = {
    "ADSI", "bool", "Console", "Convert", "Environment", "int", "int64", "Math", "ordered", "scriptblock", "string",
    "Security.Principal.NTAccount", "Security.Principal.SecurityIdentifier", "Security.Principal.WindowsBuiltInRole",
    "Security.Principal.WindowsIdentity", "Security.Principal.WindowsPrincipal",
}
ASSIGNED = {"member:[Console]::OutputEncoding"}  # the output encoding of this one process
DRIVES = {"env"}  # $env:USERPROFILE and the like, read only
# Get-Safe runs the script blocks it is given; they are part of this script and checked like the rest.
DYNAMIC_CALLS = {"$Block"}


def inventories(paths: list[Path]) -> dict[str, dict]:
    """One PowerShell run for all scripts: the inventory of each, keyed by its path."""
    run = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(INVENTORY),
         *map(str, paths)],
        capture_output=True, timeout=300, check=True,
    )
    return json.loads(run.stdout.decode("utf-8-sig"))


@cache
def inventory() -> dict:
    return inventories([SCRIPT])[str(SCRIPT)]


def violations(inv: dict) -> list[str]:
    """Everything in the script that is not on an allowlist; empty when it only reads."""
    found = [f"parse error: {e}" for e in inv["parse_errors"]]
    for c in inv["commands"]:
        name, args, where = c["name"], c["args"] or [], f"line {c['line']}"
        if c["operator"] == "Dot":
            found.append(f"{where}: dot-sourcing {c['target']}")
        if c["target"] in PROGRAMS:
            if not args or str(args[0]).casefold() not in PROGRAMS[c["target"]]:
                found.append(f"{where}: {c['target']} {' '.join(map(str, args))}")
            continue
        if name is None:
            if c["target"] not in DYNAMIC_CALLS:
                found.append(f"{where}: computed command {c['target']}")
            continue
        if name.casefold() not in COMMANDS:
            found.append(f"{where}: command {name}")
        params = [a for a in args if isinstance(a, str) and re.fullmatch(r"-[A-Za-z]\w*", a)]
        found += [f"{where}: parameter {p} of {name}" for p in params if p.casefold() not in PARAMETERS]
        if name.casefold() == "new-object":
            values = [a for a in args if a not in params]
            if "-comobject" in (p.casefold() for p in params):
                if not values or values[0] not in COM_OBJECTS:
                    found.append(f"{where}: COM object {values}")
            elif not values or values[0] not in NEW_TYPES:
                found.append(f"{where}: New-Object {values}")
    for m in inv["methods"]:
        name, where = m["member"], f"line {m['line']}"
        if m["static"]:
            if (m["type"], name) not in STATIC_METHODS:
                found.append(f"{where}: [{m['type'] or m['target']}]::{name}")
        elif name in GUARDED_METHODS:
            if not GUARDED_METHODS[name]({**m, "args": m["args"] or []}):
                found.append(f"{where}: {m['target']}.{name}({m['args']})")
        elif name not in METHODS:
            found.append(f"{where}: method {name} on {m['target']}")
    found += [f"type [{t}]" for t in inv["types"] if t not in TYPES]
    found += [f"computed member {d}" for d in inv["dynamic"]]
    found += [f"assignment to {a}" for a in inv["assigned"] if a not in ASSIGNED]
    found += [f"drive {d}:" for d in inv["drives"] if d.casefold() not in DRIVES]
    found += [f"redirection into {r}" for r in inv["redirects"] if r != "$null"]
    return found


@needs_powershell
def test_collector_parses_and_the_inventory_sees_it():
    inv = inventory()
    assert inv["parse_errors"] == []
    assert len(inv["commands"]) > 30 and len(inv["methods"]) > 20, "the inventory stopped seeing the script"


@needs_powershell
def test_collector_stays_within_the_allowlist():
    assert violations(inventory()) == []


BYPASSES = [
    "sc C:\\x.txt 'x'",  # alias of Set-Content
    "sp HKLM:\\SOFTWARE\\x -Name y -Value 1",  # alias of Set-ItemProperty
    "clear-content C:\\x.txt",
    "Get-ChildItem C:\\x | Remove-Item",
    "powercfg /change standby-timeout-ac 0",
    "& powercfg.exe /change standby-timeout-ac 0",
    '& "$env:SystemRoot\\System32\\powercfg.exe" /change standby-timeout-ac 0',
    '& "$env:SystemRoot\\System32\\powercfg.exe" /setacvalueindex SCHEME_CURRENT SUB_NONE CONSOLELOCK 0',
    '& "$env:SystemRoot\\System32\\cmd.exe" /c del x',
    "& whoami.exe /groups",  # found through PATH, where another whoami.exe can answer
    "reg add HKLM\\SOFTWARE\\x /v y /d 1",
    "cmd /c del C:\\x.txt",
    "& ('Set-' + 'Content') C:\\x.txt x",
    "$n = 'Remove-Item'; & $n C:\\x.txt",
    ". ([scriptblock]::Create('Remove-Item C:\\x.txt'))",
    "$ExecutionContext.InvokeCommand.InvokeScript('Remove-Item C:\\x.txt')",
    "iex 'Remove-Item C:\\x.txt'",
    "Start-Process notepad.exe",
    "[IO.File]::WriteAllText('C:\\x.txt', 'x')",
    "[Net.Sockets.TcpClient]::new('example.org', 80)",
    "$c = [System.Net.WebClient]::new()",
    "New-Object Net.WebClient",
    "New-Object -com WScript.Shell",
    "New-Object -ComObject WScript.Shell",
    "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateInstaller().Install()",
    "Get-CimInstance Win32_Process | Invoke-CimMethod -MethodName Terminate",
    "Get-CimInstance Win32_OperatingSystem -ComputerName server",
    "Get-CimInstance Win32_OperatingSystem -Comp server",
    "Get-ChildItem C:\\x | ForEach-Object { $_.Delete() }",
    "Get-ChildItem C:\\x | ForEach-Object { $_.Replace('C:\\y', $null) }",
    "$group = [ADSI]'WinNT://./Administratoren,group'; $group.Add('WinNT://./x')",
    "$group.Invoke('Add', 'WinNT://./x')",
    "$k.SetValue('a', 1)",
    "$o.$method()",
    "${C:\\x.txt} = 'x'",
    "'x' > C:\\x.txt",
    "'x' | Out-File C:\\x.txt",
]


@pytest.fixture(scope="module")
def planted(tmp_path_factory) -> dict[str, dict]:
    """The inventory of each bypass on its own, all read in one PowerShell run.

    The collector itself is clean (test above), so whatever the check finds comes from the bypass.
    """
    folder = tmp_path_factory.mktemp("planted")
    paths = {}
    for number, snippet in enumerate(BYPASSES):
        paths[snippet] = folder / f"bypass{number:02}.ps1"
        paths[snippet].write_text(snippet + "\n", encoding="utf-8")
    found = inventories(list(paths.values()))
    return {snippet: found[str(path)] for snippet, path in paths.items()}


@needs_powershell
@pytest.mark.parametrize("snippet", BYPASSES)
def test_allowlist_catches_known_bypasses(snippet, planted):
    assert violations(planted[snippet]), snippet


# --------------------------------------------------------------------------- text checks, on every platform

FORBIDDEN = (
    "invoke-", "add-type", "set-", "remove-", "new-item", "start-", "stop-", "restart-", "enable-", "disable-",
    "out-file", "webclient", "webrequest", "downloadstring", "http://", "https://", "encodedcommand", "iex ",
    ".setvalue(", ".deletevalue(", ".delete(", "reg.exe", "netsh", "bcdedit", "manage-bde", "ldap://",
)


def code() -> str:
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    return "\n".join(line for line in lines if not line.lstrip().startswith("#"))


def test_collector_contains_no_writing_or_network_tokens():
    text = code().casefold()
    assert [token for token in FORBIDDEN if token in text] == []


def test_adsi_reads_only_this_computer():
    # WinNT://./ is the local machine; LDAP:// or another host name would go over the network.
    paths = re.findall(r"\[ADSI\]\s*\(?\s*'([^']*)'", code(), flags=re.IGNORECASE)
    assert paths and all(path.casefold() == "winnt://./" for path in paths)


def test_collector_never_records_file_names():
    for token in ("$f.Name", "$f.FullName", "$f.BaseName", "$f.DirectoryName", "$f.Directory"):
        assert token.casefold() not in code().casefold()


# --------------------------------------------------------------------------- Python

PY_IMPORTS = {
    "__future__", "argparse", "ast", "codecs", "dataclasses", "datetime", "importlib.resources", "io", "json", "os", "pathlib", "re",
    "shutil", "sys", "textwrap", "tomllib", "typing",
}
SUBPROCESS_FILES = {"collector.py"}  # runs powershell.exe with collect.ps1, nothing else
CTYPES_FILES = {"cli.py"}  # switches on colours in the classic Windows console, nothing else
MODULES = {"os", "shutil", "subprocess", "sys", "ctypes", "windll", "kernel32"}
MODULE_ATTRIBUTES = {
    "os.environ", "os.name", "shutil.get_terminal_size", "subprocess.run", "subprocess.TimeoutExpired",
    "sys.stdout", "sys.stderr", "sys.argv", "sys.exit", "sys.flags",
    "ctypes.windll", "ctypes.c_uint32", "ctypes.byref", "windll.kernel32",
    # the console of this process: its handle, its mode and its code page
    "kernel32.GetStdHandle", "kernel32.GetConsoleMode", "kernel32.SetConsoleMode", "kernel32.GetConsoleOutputCP",
}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "breakpoint"}
FORBIDDEN_ATTRIBUTES = {
    "unlink", "rmdir", "rmtree", "removedirs", "remove", "rename", "chmod", "system", "popen", "startfile", "kill",
    "import_module",
}


def python_violations(source: str, filename: str) -> list[str]:
    found = []
    allowed = set(PY_IMPORTS)
    if filename in SUBPROCESS_FILES:
        allowed.add("subprocess")
    if filename in CTYPES_FILES:
        allowed.add("ctypes")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found += [f"import {a.name}" for a in node.names if a.name not in allowed]
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            # "from importlib import resources" is fine; "from os import system" is not.
            names = [f"{node.module}.{a.name}" for a in node.names]
            found += [f"from {node.module} import {n.rsplit('.', 1)[1]}" for n in names
                      if node.module not in allowed and n not in allowed]
            if node.module in MODULES:
                found += [f"from {node.module} import {n.rsplit('.', 1)[1]}" for n in names
                          if n not in MODULE_ATTRIBUTES]
        elif isinstance(node, ast.Attribute):
            # ctypes.windll.kernel32.X counts as kernel32.X
            owner = node.value.attr if isinstance(node.value, ast.Attribute) else getattr(node.value, "id", None)
            if owner in MODULES and f"{owner}.{node.attr}" not in MODULE_ATTRIBUTES:
                found.append(f"{owner}.{node.attr}")
            if node.attr in FORBIDDEN_ATTRIBUTES:
                found.append(f".{node.attr}")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALLS:
            found.append(f"{node.func.id}()")
        elif isinstance(node, ast.keyword) and node.arg == "shell":
            found.append("shell=")
    return found


def test_python_stays_within_the_allowlist():
    files = sorted(SRC.rglob("*.py"))
    assert len(files) > 5
    found = {p.name: python_violations(p.read_text(encoding="utf-8"), p.name) for p in files}
    assert {name: v for name, v in found.items() if v} == {}


def test_the_collector_runs_powershell_and_nothing_else():
    from lexshield.collector import POWERSHELL as COMMAND

    assert COMMAND[0] == "powershell.exe" and COMMAND[-1] == "-File"


@pytest.mark.parametrize(
    "source",
    [
        "import os\nos.system('del x')",
        "import os\nos.popen('x')",
        "from os import system",
        "import socket",
        "from urllib.request import urlopen",
        "import http.client",
        "import ctypes",
        "import importlib\nimportlib.import_module('socket')",
        "from importlib import import_module",
        "__import__('socket')",
        "exec('import socket')",
        "import subprocess\nsubprocess.run(['cmd'])",
        "from pathlib import Path\nPath('x').unlink()",
        "import shutil\nshutil.rmtree('x')",
        "import winreg",
    ],
)
def test_python_check_catches_known_bypasses(source):
    assert python_violations(source, "report.py"), source


@pytest.mark.parametrize(
    "source",
    [
        "import ctypes; ctypes.windll.kernel32.DeleteFileW('x')",
        "import ctypes; ctypes.windll.advapi32.RegSetValueExW()",
        "import ctypes; ctypes.WinDLL('advapi32')",
        "import ctypes; kernel32 = ctypes.windll.kernel32; kernel32.CreateFileW('x')",
    ],
)
def test_ctypes_is_limited_to_the_console(source):
    assert python_violations(source, "cli.py"), source
