# Check catalogue

Run each check on every build in scope. Record the result as present, partial, absent, unchecked or does not apply.

## A. JavaScript bundle (React Native)

| Check | How | Severity guide |
|---|---|---|
| Secret-shaped strings | `scan_secrets.py` on the bundle | secret if the value grants access without the app |
| Keys inside URLs | Raw byte scan, same script | abuse-risk (cloud API keys) |
| Header names next to long strings | Read the function that builds requests. Look for names like `bypass`, `api-key`, `signature`. | secret if the string is a credential |
| Client-side signing | Search for digest calls (`SHA1`, `HMAC`) next to long strings | secret when all inputs ship in the app |
| Third-party SDK keys | List analytics, error tracking, CMS and push keys | abuse-risk (event injection, content read) |
| API surface | Count operation names, feature-flag keys, storage keys, source file names | info |
| Debug-only paths | Search for staging hosts, test accounts, feature switches | review |

Notes:
- Build-time environment plugins inline values as plain strings. Every value in the build environment is public.
- A key chosen with a platform check at runtime ships for both platforms.

## B. Android package

| Check | How | Severity guide |
|---|---|---|
| Manifest flags | `aapt2 dump xmltree --file AndroidManifest.xml app.apk`: `debuggable`, `allowBackup`, `usesCleartextTraffic`, `networkSecurityConfig`, exported components | info to abuse-risk |
| Backup rules | Read `res/xml` backup and data-extraction files. When a rule file has `<include>`, only the listed paths are backed up. | abuse-risk if tokens are in a backed-up path |
| Network security config | Check user-CA trust and cleartext domains. Check that production references the file. | info (inert files) to abuse-risk |
| Resources | `aapt2 dump resources app.apk` for `google_api_key`, `project_id`, `app_id` | info (public by design) |
| Assets | List `assets/`. Look for config, container, script and debug-meta files. | info |
| Classes | `dexdump -l plain classes*.dex`. Count classes. Find the share with short names. | info |
| Keep rules | Read the `proguard` or R8 rules in source. Find the packages kept by name. | info |
| Native libraries | List `lib/<abi>/*.so` | info |
| Signature | `apksigner verify --print-certs` | info |

## C. iOS package

| Check | How | Severity guide |
|---|---|---|
| Info.plist | `plutil -p Payload/App.app/Info.plist`: URL schemes, API keys, ATS settings | info to abuse-risk |
| ATS | `NSAllowsArbitraryLoads` and the web, media and local-network exceptions | info |
| Firebase file | `GoogleService-Info.plist` | info (public by design) |
| Entitlements | `codesign -d --entitlements - App.app`: associated domains, push, keychain groups | info |
| Encryption | `otool -l` and look for `cryptid 1`. A store build is encrypted, so skip the main binary. | scope note |
| Strip settings | `xcodebuild -showBuildSettings`: `STRIP_STYLE`, `COPY_PHASE_STRIP`, `GCC_SYMBOLS_PRIVATE_EXTERN` | info |
| Bundle | Hermes: run `hermesc` on `main.jsbundle` | see section A |

## D. Device storage (source review)

An archive does not show runtime storage. Read the source and the library code.

| Check | Question |
|---|---|
| Token store | Where does the key-value store write? Is it encrypted? |
| iOS backup | Is that directory in `Documents` or `Library/Application Support` without the exclude-from-backup flag? |
| Android backup | Is the path in a domain that the backup rules include? |
| Other SDK stores | Do third-party SDK preferences hold session tokens? |

## E. Hardening claims

For each hardening setting, ask: which layer can it reach? Compare the artefact before and after. Compare the same findings in both. Write the result as a table: setting, layer reached, findings that changed.

## F. Tool evaluation

Before you adopt a reverse-engineering tool for repeated use, test five things:

1. Can it read your bundle format? Run it on a real bundle.
2. What does it install? Check its dependencies and its edits to agent or editor configuration.
3. What else must you download? Some tools need a decompiler or paid disassembler.
4. How long does one call take on a real package?
5. Does it give evidence you can audit (hash, version, limits)?

A small script around standard tools often wins for CI.

## Severity guide

- **secret:** A value that must not be public. A person can use it without the app.
- **abuse-risk:** Public by design, but a person can misuse it. Examples: cloud API keys, analytics write keys, unprotected local tokens.
- **info:** Information only. Examples: class names, feature flags, public app identifiers.
