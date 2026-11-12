---
name: mobile-app-exposure-audit
description: Use when asked what a person can learn from a mobile app's release build, whether secrets or API keys ship inside an iOS or Android app, whether R8, ProGuard or iOS strip settings protect an app, or to make a shareable HTML report of app-binary exposure. Covers React Native (Hermes), native Android and native iOS builds.
---

# Mobile app exposure audit

## Overview

A shipped app is a public file. Anyone can download it and read it. This skill finds what a person can read, ranks it, and writes a neutral HTML report.

**Core rule:** Measure the real release artefact. Do not trust build settings or source code alone. Check every count twice before you publish it.

## When to use

- A team asks "what can an attacker learn from our app?"
- You must check a release candidate for secrets before launch.
- You must decide if code shrinking or symbol stripping is enough.
- You must evaluate a reverse-engineering tool for repeated use.

Do not use this skill to attack an app you do not own or have permission to test.

## Workflow

Follow the steps in order. The full procedure is in `PLAYBOOK.md` at the repository root. The check list is in `references/checks.md`.

1. **Get permission and builds.** Ask for the apps in scope. Get the store release (or release candidate), plus one CI build. Work locally. Never upload a binary to an outside service.
2. **Identify the stack.** Unzip the package. A file `index.android.bundle` or `main.jsbundle` means React Native. Check the first bytes: Hermes bytecode starts with `c6 1f bc 03`.
3. **Scan the bundle.** Run `python3 scripts/scan_secrets.py <bundle> --hermesc <path>`. The `hermesc` version must match the bytecode version. Then scan the unzipped package folder with the same script.
4. **Read the package.** Use `aapt2` and `dexdump` for Android, and `plutil` and `codesign` for iOS. Use `references/checks.md` for the list.
5. **Classify each finding.** Use `secret`, `abuse-risk` or `info`. Write what, evidence, fix and owner.
6. **Re-measure.** Run every count again on the final builds. Write a Corrections section for anything that changed.
7. **Write the report.** Fill a findings JSON file. Use `assets/example-findings.json` as the model. Run `python3 scripts/render_report.py findings.json report.html`. Read `references/findings-schema.md` for the fields.
8. **Hand over.** Give the report to the security owner first. Do not share it wider until they agree.

## Rules

- **Mask every value.** Show the first four and last two characters. The renderer refuses unmasked keys.
- **Never paste a found value** into a ticket, chat or commit.
- **Check the parsed string count** against the header count. A lower count means the parser missed entries.
- **Scan raw bytes too.** A key inside a URL does not start a string.
- **State what you did not check.** Put it in the Scope section.
- **Separate source review from binary evidence.** An iOS archive does not show runtime storage.

## Red flags

| Thought | Reality |
|---|---|
| "R8 or strip is on, so we are safe." | They change DEX names and symbols only. The bundle, assets and resources stay readable. |
| "The tool gave zero results." | Check that the tool can read the format. Zero from an unsupported file is not a pass. |
| "The first scan is enough." | First scans miss things. Re-measure on the final builds. |
| "The key is public by design." | Public does not mean safe. Check quota and restriction. |

## Common mistakes

- Using a `hermesc` that does not match the bytecode version. The tool fails or reads wrong.
- Reading only one kind of string-table entry.
- Reporting a build setting as a result without opening the artefact.
- Marking a finding "absent" from a single scan.
