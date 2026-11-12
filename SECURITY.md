# Security policy

## Intended use

This project helps owners check their own apps. Test only apps you own or have written permission to test. Do not use it to attack other apps or to take credentials from them.

## Report a problem in this project

Report a vulnerability in the scripts (for example, a way to run code through a crafted app file) in private. Use GitHub's "Report a vulnerability" button on the Security tab. Do not open a public issue.

Include: what you did, what you expected, what happened, and the version (commit hash). I aim to reply within 7 days.

## Report a secret you found in this repository

This repository holds no real credentials. All example values are invented. If you find a value that looks real, report it in private as above.

## Handle scan results with care

- Scan results and reports can point to real secrets in a real app. Share them only with the app's security owner.
- Reports hold masked values only. Do not paste full values into tickets, chat or commits.
- Rotate any secret that you find in a shipped build. Removing it from the next release is not enough, because old builds stay public.

## Scope

In scope: `scan_secrets.py`, `render_report.py` and the documents.
Out of scope: vulnerabilities in third-party tools that the playbook names, such as `hermesc`, `jadx`, `apktool` and `ipatool`. Report those to their owners.

## No warranty

The software is provided "as is", as the MIT license says. The scanner finds secret-shaped strings. It does not prove that a value is a live credential, and it can miss secrets.
