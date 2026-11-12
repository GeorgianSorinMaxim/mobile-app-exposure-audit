# Mobile app exposure playbook

Use this playbook to find out what a person can learn from your iOS or Android release build. It needs no special access. It takes one to two days for one app.

## 1. The idea

Your app is a public file. Anyone can download it from a store. They can unzip it and read most of it. Build tools that rename code or strip symbols do not hide strings, assets or configuration.

Ask three questions:

1. Which **secrets** ship in the build?
2. Which **public values** can someone misuse?
3. What does the build **tell a person** about your app?

## 2. Before you start

| Item | Detail |
|---|---|
| Permission | Test only apps you own or have written permission to test. |
| Builds | Get the live store build, the next release candidate and one CI build. |
| Place | Work on a local machine. Do not upload binaries to outside services. |
| Tools | `unzip`, Python 3, `aapt2` and `dexdump` (Android build-tools), `jadx`, `apktool`, `plutil`, `codesign`, `otool`, `ipatool` (to download your own IPA), and `hermesc` for React Native. |
| Reader | Name a security owner. They see the report first. |

## 3. Get the builds

- **Android:** Download the universal APK from your store console. Or build a release APK in CI. Record the version, build number and SHA-256.
- **iOS:** Download your own IPA with `ipatool`, or use a simulator build from CI. A store IPA has an encrypted main binary. The JavaScript bundle, property lists and resources stay readable.
- **Record each build** in a table: name, version, source, hash, hardening settings (shrinker on or off).

## 4. Identify the stack

```sh
unzip -o app.apk -d apk/        # for iOS: unzip app.ipa -d ipa/
ls apk/assets ipa/Payload/*.app
```

| You see | Stack |
|---|---|
| `index.android.bundle` or `main.jsbundle` | React Native |
| First bytes `c6 1f bc 03` | Hermes bytecode |
| `libflutter.so`, `App.framework` | Flutter. Use a Flutter-specific tool. |
| Only DEX classes and resources | Native Android |

## 5. Read the JavaScript bundle (React Native)

This is usually where the secrets are. Build tools inline every build-time environment value as a plain string.

1. Find the Hermes version: `hermesc -b -dump-bytecode app.bundle | head`. The `hermesc` must match the bytecode version. If it does not, install the `hermes-compiler` version from the app's lockfile at that release.
2. Run the scanner:

   ```sh
   python3 skills/mobile-app-exposure-audit/scripts/scan_secrets.py \
       apk/assets/index.android.bundle --hermesc ./hermesc --json scan.json
   ```

3. Check the note at the top: `parsed all N strings`. If it says the count differs from the header, stop and fix the parser.
4. Open the function next to each hit. Use the disassembly: `hermesc -b -dump-bytecode -pretty-disassemble bundle > bundle.hasm`. Look for header names, signing code and the origin of each string.
5. Decide: is this a credential, a public identifier, or a key a person can abuse?

**Traps**

- `strings` is useless on Hermes. The strings have no NUL terminators.
- The string table has two entry kinds. Read both.
- The pretty disassembly cuts long strings inside function bodies. Read full values from the string table section.
- A key inside a URL does not start a string. Scan raw bytes too.
- Count keys by distinct value. Two platform keys chosen at runtime both ship on both platforms.

## 6. Read the package

**Android**

```sh
aapt2 dump badging app.apk
aapt2 dump xmltree --file AndroidManifest.xml app.apk
aapt2 dump resources app.apk | grep -E 'string/(google|gcm|firebase|project|default_web)'
dexdump -l plain apk/classes*.dex | grep 'Class descriptor' | wc -l
```

Read: manifest flags, backup rules, network security config, exported components, resource strings, `assets/`, native library names.

**iOS**

```sh
plutil -p ipa/Payload/App.app/Info.plist
plutil -p ipa/Payload/App.app/GoogleService-Info.plist
codesign -d --entitlements - ipa/Payload/App.app
```

Read: URL schemes, keys in `Info.plist`, ATS exceptions, associated domains, encryption state.

Full list: `skills/mobile-app-exposure-audit/references/checks.md`.

## 7. Review storage in source

An archive does not show what the app writes at runtime. Read the code and the storage library.

- Where does the app keep session tokens?
- Is the store encrypted?
- Is the directory in a backup? Android: read the backup rule files. iOS: check the exclude-from-backup flag.
- Do third-party SDKs keep tokens in shared preferences?

Mark these findings "source review" in the report.

## 8. Classify and write findings

| Severity | Meaning | Example |
|---|---|---|
| secret | Must not be public. A person can use it without the app. | Hosting bypass token. Shared signing key. |
| abuse-risk | Public by design, but misuse is possible. | Cloud API key. Analytics write key. Unprotected token store. |
| info | Information only. | Class names. Feature flags. Public app IDs. |

For each finding write four things:

- **What** it is and where it lives.
- **Evidence:** the function, file or string index. Masked value only.
- **Fix:** one concrete action.
- **Owner:** the team that can act.

Fix patterns:

| Problem | Fix |
|---|---|
| Shared secret in the bundle | Move the check to the server. Use app attestation or per-install secrets. Rotate the secret. Keep the old one working until users update. |
| Client-side signing | Sign on the server. A key that ships in the app is not a key. |
| Cloud API key in the app | Restrict by API. Set quota caps and spend alerts. Know that an app restriction does not work if your HTTP client sends no package headers. |
| Tokens in backups | Exclude the directory from backup. Encrypt with a key in the platform keystore. |
| Analytics or CMS write keys | Turn on server-side auth where the vendor offers it. Remove preview or admin tokens from the app. |

## 9. Test the hardening claims

Compare a build with hardening off and a build with it on. Count what changed:

- Class count and the share of renamed classes.
- Whether any finding moved or went away.

Expected result: hardening reduces DEX readability and size. It does not remove bundle, asset or resource findings. Keep it for size and store rules, not for secrecy.

## 10. Re-measure

Run every count again on the final builds. Use raw byte scans as well as parsed scans. Write a **Corrections** section for each number or claim that changed. This step finds real errors. Plan time for it.

## 11. Evaluate tools (optional)

If you consider an automated reverse-engineering toolkit:

1. Test it on your real bundle format first.
2. List what it installs and what you must add.
3. Time one call on a real package.
4. Compare its results with the standard tools.

Adopt it for repeated use only if it reads the artefact that holds your exposure. For many React Native apps, a short script around `hermesc`, `aapt2`, `dexdump` and `jadx` is enough.

## 12. Report

1. Fill `findings.json`. Use `skills/mobile-app-exposure-audit/assets/example-findings.json` as the model.
2. Run `python3 skills/mobile-app-exposure-audit/scripts/render_report.py findings.json report.html`.
3. Give the report to the security owner. Wait for their agreement before you share wider.
4. Open one consolidated follow-up ticket. Group fixes by priority: P0 for secrets, P1 for abuse risks, P2 for the rest.

## 13. Make it repeatable

- Run `scan_secrets.py` on each release candidate. The script exits with code 1 when it finds a secret. Use that to fail the CI step.
- Keep a short allowlist of reviewed public values. Review it each quarter.
- Re-run the full playbook after a major framework upgrade.

## 14. Report checklist

- [ ] Every build has a version, source and hash.
- [ ] Every value is masked.
- [ ] Every finding has what, evidence, fix and owner.
- [ ] Every count was measured twice.
- [ ] Source-review findings are marked.
- [ ] The Scope section lists what you did not check.
- [ ] The security owner read the report.
