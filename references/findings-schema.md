# Findings JSON schema

`render_report.py` reads one JSON file. Every key except `findings` is optional. A section with no data does not appear.

```json
{
  "eyebrow": "Type · date",
  "title": "What a person learns from the <App> release builds",
  "summary": { "headline": "", "found": "", "meaning": "", "do_first": ["", ""] },
  "builds": [{ "id": "rc", "name": "Android RC 1.2.0", "description": "" }],
  "matrix_note": "",
  "layers": [{ "name": "", "reach": "", "note": "", "findings": ["F1"] }],
  "layers_conclusion": "",
  "findings": [{
    "id": "F1", "title": "", "subtitle": "",
    "severity": "secret | abuse-risk | info",
    "presence": { "rc": "present | partial | absent | unchecked | na" },
    "presence_note": { "rc": "Same value" },
    "what": "", "evidence": "", "impact": "", "open_point": "", "fix": "", "owner": ""
  }],
  "corrections": [{ "title": "", "text": "" }],
  "method": [{ "title": "", "text": "" }],
  "tools": [{ "tool": "", "target": "", "result": "" }],
  "hardening": { "title": "", "verdict": "", "points": [""] },
  "next_steps": [{ "priority": "P0", "title": "", "text": "", "owners": [""] }],
  "scope": { "analysed": [""], "not_analysed": [""] },
  "reproduce": "shell commands, plain text",
  "footer": ""
}
```

Rules:
- `presence` keys must match the `id` values in `builds`.
- Write masked values only: first four and last two characters, for example `AIza…bA`. The renderer stops when it sees a full key, JWT, private key block or long hex string.
- Use `\n` in a text field to start a new paragraph.
- Write short sentences. One idea per sentence.

Render:

```sh
python3 scripts/render_report.py findings.json report.html
```

The output is one HTML file. It has no external fonts, scripts or images. It follows the system light or dark theme and has a theme button.
