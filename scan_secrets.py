#!/usr/bin/env python3
"""Find secret-shaped strings in a mobile app build. Values are always masked.

Inputs (one or more paths):
  * a Hermes bytecode bundle (index.android.bundle, main.jsbundle) - needs hermesc
  * a Hermes disassembly file (*.hasm) made with hermesc
  * any other file or a directory (for example an unzipped APK or IPA)

Two scans run on every input:
  1. String table scan (Hermes only): reads ALL string entries, both the
     "s<n>" and the "i<n>" kinds, and checks the count against the header.
  2. Raw byte scan: finds key shapes inside longer strings, for example a
     key inside a URL. A string table scan alone misses these.

Exit code: 0 = no finding at or above --fail-on, 1 = findings, 2 = tool error.
"""
import argparse
import json
import os
import re
import subprocess
import sys

# (rule id, severity, regex). Severity: secret > abuse-risk > review.
RULES = [
    ("private-key-block", "secret", rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("aws-access-key-id", "secret", rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("stripe-live-key", "secret", rb"\b[sr]k_live_[0-9A-Za-z]{16,}"),
    ("github-token", "secret", rb"\bgh[pousr]_[0-9A-Za-z]{36,}"),
    ("slack-token", "secret", rb"\bxox[baprs]-[0-9A-Za-z-]{10,}"),
    ("credentials-in-url", "secret", rb"\b[a-z][a-z0-9+.-]{1,12}://[^\s/:@\"']{2,}:[^\s/@\"']{3,}@[\w.-]+"),
    ("google-api-key", "abuse-risk", rb"AIza[0-9A-Za-z_-]{35}"),
    ("sentry-dsn", "abuse-risk", rb"https://[0-9a-f]{32}@[\w.-]+/\d+"),
    ("jwt", "review", rb"\beyJ[0-9A-Za-z_-]{8,}\.eyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}"),
    ("long-hex-string", "review", rb"(?<![0-9A-Fa-f])[0-9a-f]{32,64}(?![0-9A-Fa-f])"),
]
ORDER = {"review": 0, "abuse-risk": 1, "secret": 2}
# Identifier names that suggest a credential. Names only, never values.
NAME_HINT = re.compile(r"(secret|password|passwd|private[_-]?key|api[_-]?key|apikey|bypass|auth[_-]?token|access[_-]?token|client[_-]?secret)", re.I)
ENTRY = re.compile(r"^([si])(\d+)\[(?:ASCII|UTF-16)[^\]]*\](?: #[0-9A-F]+)?: ?(.*)$")


def mask(value: str) -> str:
    """First four and last two characters only."""
    return value if len(value) <= 8 else f"{value[:4]}…{value[-2:]} ({len(value)})"


def run_hermesc(hermesc: str, bundle: str) -> str:
    cmd = [hermesc, "-b", "-dump-bytecode", "-pretty-disassemble", bundle]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=600)
    except FileNotFoundError:
        sys.exit(f"error: hermesc not found at {hermesc!r}. Use --hermesc.")
    if proc.returncode != 0 or "Global String Table" not in proc.stdout:
        sys.exit(
            "error: hermesc could not read this bundle. The bytecode version must match "
            "the hermesc version. Use the hermesc from the same release as the build.\n"
            + proc.stderr[:400]
        )
    return proc.stdout


def parse_string_table(disasm: str):
    """Return (strings, identifier names, header count). Reads s and i entries."""
    m = re.search(r"String count:\s*(\d+)", disasm)
    header = int(m.group(1)) if m else None
    start = disasm.find("Global String Table:")
    if start < 0:
        return [], [], header
    strings, names, current = [], [], None
    for line in disasm[start:].splitlines()[1:]:
        e = ENTRY.match(line)
        if e:
            current = [e.group(1), e.group(3)]
            (strings if e.group(1) == "s" else names).append(current)
        elif line.strip() == "" or re.match(r"^[A-Z][\w ]+:$", line):
            if line.strip():  # next section header ends the table
                break
            current = None
        elif current is not None:  # a string with an embedded newline
            current[1] += "\n" + line
    return [s[1] for s in strings], [n[1] for n in names], header


def scan_bytes(data: bytes, source: str, where: str, out: dict):
    for rule, sev, rx in RULES:
        for m in re.finditer(rx, data):
            val = m.group(0).decode("latin-1")
            out.setdefault((rule, val), {"rule": rule, "severity": sev, "masked": mask(val), "where": set()})["where"].add(f"{source}:{where}")


def iter_files(path: str):
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for f in files:
                yield os.path.join(root, f)
    else:
        yield path


def is_hermes(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(8) == bytes.fromhex("c61fbc03c103191f")
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--hermesc", default="hermesc", help="path to a hermesc that matches the bundle version")
    ap.add_argument("--json", help="write findings to this file")
    ap.add_argument("--fail-on", choices=["secret", "abuse-risk", "review", "never"], default="secret")
    ap.add_argument("--max-file-mb", type=int, default=200)
    args = ap.parse_args()

    found, names, notes = {}, set(), []
    for root in args.paths:
        for path in iter_files(root):
            if os.path.getsize(path) > args.max_file_mb * 1_000_000:
                notes.append(f"skipped (too large): {path}")
                continue
            if path.endswith(".hasm"):
                disasm = open(path, errors="replace").read()
            elif is_hermes(path):
                disasm = run_hermesc(args.hermesc, path)
            else:
                disasm = None
            if disasm is not None:
                strs, idents, header = parse_string_table(disasm)
                total = len(strs) + len(idents)
                if header is not None and total != header:
                    notes.append(f"{path}: parsed {total} strings but the header says {header}. Do not trust a count that differs.")
                else:
                    notes.append(f"{path}: parsed all {total} strings ({len(strs)} s-kind, {len(idents)} i-kind).")
                for s in strs:
                    scan_bytes(s.encode("utf-8", "replace"), path, "string-table", found)
                names.update(n for n in idents if NAME_HINT.search(n))
            if not path.endswith(".hasm"):
                with open(path, "rb") as fh:
                    scan_bytes(fh.read(), path, "raw-bytes", found)

    findings = sorted(
        ({**f, "where": sorted(f["where"])} for f in found.values()),
        key=lambda f: (-ORDER[f["severity"]], f["rule"], f["masked"]),
    )
    result = {"findings": findings, "suspicious_names": sorted(names), "notes": notes}
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(result, fh, indent=2)
    for n in notes:
        print("note:", n)
    for f in findings:
        print(f"[{f['severity']:<10}] {f['rule']:<20} {f['masked']}  ({len(f['where'])} location(s))")
    if names:
        print("suspicious identifier names (check the code next to each):", ", ".join(sorted(names)))
    if not findings:
        print("No secret-shaped strings found.")
    if args.fail_on != "never" and any(ORDER[f["severity"]] >= ORDER[args.fail_on] for f in findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
