# mobile-app-exposure-audit

Find out what a person can learn from your mobile app's release build. Get a neutral HTML report.

## What is in this repository

| Path | Purpose |
|---|---|
| `PLAYBOOK.md` | Step-by-step method for people. Read this first. |
| `skills/mobile-app-exposure-audit/SKILL.md` | The skill for an AI coding agent. |
| `skills/mobile-app-exposure-audit/scripts/scan_secrets.py` | Secret-shape scanner. Reads Hermes bundles and plain files. Masks all values. |
| `skills/mobile-app-exposure-audit/scripts/render_report.py` | Turns a findings JSON file into one HTML report. No branding. No network. |
| `skills/mobile-app-exposure-audit/references/` | Check catalogue and JSON schema. |
| `skills/mobile-app-exposure-audit/assets/example-findings.json` | Example with invented data. |

## Quick start

```sh
# 1. Scan a bundle (Python 3.9 or later; hermesc for Hermes bundles)
python3 skills/mobile-app-exposure-audit/scripts/scan_secrets.py \
    path/to/index.android.bundle --hermesc ./hermesc

# 2. Try the report with the example data
python3 skills/mobile-app-exposure-audit/scripts/render_report.py \
    skills/mobile-app-exposure-audit/assets/example-findings.json report.html
```

Install the skill: copy `skills/mobile-app-exposure-audit/` into your agent's skills folder (for Claude Code: `~/.claude/skills/`).

## Safety

- Test only apps you own or have written permission to test.
- Work locally. Do not upload binaries.
- Reports hold masked values only. The renderer refuses full keys.
- Give a report to the security owner before you share it.

## Limits

- The scanner finds secret *shapes*. It does not prove a value is a live credential. Always read the code next to a hit.
- It does not analyse FairPlay-encrypted iOS binaries, Flutter AOT snapshots or server behaviour.
- Storage and backup findings need a source review.
