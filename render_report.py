#!/usr/bin/env python3
"""Render a findings JSON file as one self-contained HTML report.

No branding, no external fonts, scripts or images. Works offline.
Usage: python3 render_report.py findings.json report.html
Schema: see references/findings-schema.md
"""
import json
import re
import sys
from html import escape as e

PRESENCE = {
    "present": ("✔", "Present"),
    "partial": ("◐", "Partly checked"),
    "absent": ("✘", "Absent"),
    "unchecked": ("○", "Not checked"),
    "na": ("—", "Does not apply"),
}
SEV = {"secret": "Secret", "abuse-risk": "Abuse risk", "info": "Info"}
SEV_ORDER = {"secret": 0, "abuse-risk": 1, "info": 2}
# A value that looks like a full credential must never reach the report.
LEAK = re.compile(r"AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|\b[sr]k_live_\w{16,}|-----BEGIN [A-Z ]*PRIVATE KEY|\beyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]{8,}|\b[0-9a-f]{32,}\b")

CSS = """
:root{--bg:#fff;--fg:#1a1d23;--mut:#5b6472;--card:#f5f6f8;--line:#dfe2e8;--acc:#2456c7;
--sec:#b3261e;--secbg:#fde8e6;--abu:#8a5300;--abubg:#fff1d6;--inf:#35566f;--infbg:#e6eef4;--ok:#1b6e3c}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#14161a;--fg:#e8eaee;--mut:#9aa3b2;--card:#1d2026;--line:#2e333c;--acc:#8db0ff;
--sec:#ff9f97;--secbg:#3a1c1a;--abu:#f2c26b;--abubg:#3a2c10;--inf:#9dc3dd;--infbg:#1c2b36;--ok:#7bd39a}}
:root[data-theme=dark]{--bg:#14161a;--fg:#e8eaee;--mut:#9aa3b2;--card:#1d2026;--line:#2e333c;--acc:#8db0ff;--sec:#ff9f97;--secbg:#3a1c1a;--abu:#f2c26b;--abubg:#3a2c10;--inf:#9dc3dd;--infbg:#1c2b36;--ok:#7bd39a}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:0 16px 80px}
nav{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--line);z-index:5;overflow-x:auto;white-space:nowrap}
nav a{display:inline-block;padding:10px 12px;color:var(--mut);text-decoration:none;font-size:14px}nav a:hover{color:var(--acc)}
header{padding:40px 0 8px}.eyebrow{color:var(--mut);font-size:14px}
h1{font-size:clamp(26px,5vw,38px);line-height:1.15;margin:8px 0 12px}h2{font-size:22px;margin:44px 0 6px}h3{font-size:17px;margin:20px 0 6px}
p{margin:6px 0}.lead{font-size:18px}.mut{color:var(--mut)}code{font:13px ui-monospace,Menlo,Consolas,monospace;background:var(--card);padding:1px 5px;border-radius:4px;word-break:break-word}
pre{background:var(--card);padding:14px;border-radius:8px;overflow-x:auto;font:13px/1.5 ui-monospace,Menlo,Consolas,monospace}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}.card b{display:block;margin-bottom:4px}
.stats{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}.stat{background:var(--card);border-radius:10px;padding:10px 16px;min-width:120px}.stat .n{font-size:26px;font-weight:700;display:block}.stat span.l{color:var(--mut);font-size:13px}
.tag{display:inline-block;font-size:12px;font-weight:600;padding:2px 8px;border-radius:99px;margin-left:6px;vertical-align:middle}
.t-secret{background:var(--secbg);color:var(--sec)}.t-abuse-risk{background:var(--abubg);color:var(--abu)}.t-info{background:var(--infbg);color:var(--inf)}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px}table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{background:var(--card);font-weight:600}tr:last-child td{border-bottom:0}
td.p{white-space:nowrap}.p-present{color:var(--sec);font-weight:600}.p-absent{color:var(--ok);font-weight:600}.legend{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:14px;color:var(--mut);margin:8px 0}
.layers{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}.layer .reach{font-size:12px;font-weight:600;color:var(--mut)}
.chip{display:inline-block;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:1px 8px;margin:2px 4px 2px 0;font-size:13px;color:var(--acc);text-decoration:none}
.callout{border-left:4px solid var(--acc);background:var(--card);padding:10px 14px;border-radius:0 8px 8px 0;margin:16px 0}
.tools{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}input[type=search]{flex:1;min-width:200px;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font:inherit}
.seg button,#expandAll,#theme{background:var(--card);border:1px solid var(--line);color:var(--fg);padding:7px 12px;font:inherit;font-size:14px;cursor:pointer;border-radius:8px}.seg button[aria-pressed=true]{background:var(--acc);color:var(--bg);border-color:var(--acc)}
details.finding{border:1px solid var(--line);border-radius:10px;margin:8px 0;background:var(--bg)}details.finding>summary{cursor:pointer;padding:12px 14px;list-style:none}details.finding>summary::-webkit-details-marker{display:none}
details.finding[open]>summary{border-bottom:1px solid var(--line)}.fid{font-weight:700;margin-right:8px}.fsub{display:block;color:var(--mut);font-size:14px;margin-top:2px}
dl{margin:0;padding:12px 14px;display:grid;grid-template-columns:100px 1fr;gap:8px 14px}dt{font-weight:600;color:var(--mut)}dd{margin:0;min-width:0}
.step{border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:8px 0}.step label{display:flex;gap:10px;font-weight:600;cursor:pointer}.pri{font-size:12px;font-weight:700;color:var(--mut)}
ol.steps{padding-left:20px}ol.steps li{margin:8px 0}.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
#theme{margin-left:auto;position:sticky;right:0}footer{margin-top:50px;color:var(--mut);font-size:14px}
@media (max-width:600px){dl{grid-template-columns:1fr}dt{margin-top:6px}}
@media print{nav,.tools,#theme{display:none}details.finding{break-inside:avoid}}
"""

JS = """
(function(){
 var items=[].slice.call(document.querySelectorAll('.finding')),q=document.getElementById('q'),cnt=document.getElementById('count'),sev='all';
 function apply(){var t=q.value.trim().toLowerCase(),n=0;items.forEach(function(el){var ok=(sev==='all'||el.dataset.sev===sev)&&(!t||el.textContent.toLowerCase().indexOf(t)>-1);el.hidden=!ok;if(ok)n++});cnt.textContent='Showing '+n+' of '+items.length+' findings.'}
 q.addEventListener('input',apply);
 var segs=[].slice.call(document.querySelectorAll('.seg button'));
 segs.forEach(function(b){b.addEventListener('click',function(){sev=b.dataset.f;segs.forEach(function(x){x.setAttribute('aria-pressed',x===b?'true':'false')});apply()})});
 var open=false;document.getElementById('expandAll').addEventListener('click',function(){open=!open;items.forEach(function(el){el.open=open});this.textContent=open?'Collapse all':'Expand all'});
 function hash(){var el=document.getElementById(location.hash.slice(1));if(el&&el.classList.contains('finding')){el.hidden=false;el.open=true}}
 window.addEventListener('hashchange',hash);hash();
 var th=document.getElementById('theme');th.addEventListener('click',function(){var r=document.documentElement,d=r.getAttribute('data-theme')==='dark'||(!r.getAttribute('data-theme')&&matchMedia('(prefers-color-scheme:dark)').matches);r.setAttribute('data-theme',d?'light':'dark')});
})();
"""


def paras(text):
    return "".join(f"<p>{e(p)}</p>" for p in str(text).split("\n") if p.strip())


def check_masked(data):
    """Stop the render when any text holds a full credential."""
    bad = [m.group(0)[:6] + "…" for m in LEAK.finditer(json.dumps(data))]
    if bad:
        sys.exit("error: the findings file holds unmasked values (" + ", ".join(sorted(set(bad))[:5]) + "). Mask them to first 4 and last 2 characters, then run again.")


def render(d):
    builds = d.get("builds", [])
    findings = sorted(d.get("findings", []), key=lambda f: (SEV_ORDER.get(f.get("severity", "info"), 3), f["id"]))
    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in SEV}
    nav = [("summary", "Summary")]
    out = []

    # Header and summary
    s = d.get("summary", {})
    out.append(f'<header id="summary"><div class="eyebrow">{e(d.get("eyebrow", ""))}</div><h1>{e(d.get("title", "Mobile app exposure report"))}</h1>'
               f'<p class="lead">{e(s.get("headline", ""))}</p>')
    cards = [("Found", s.get("found")), ("What it means", s.get("meaning"))]
    out.append('<div class="cards">' + "".join(f"<div class='card'><b>{h}</b>{paras(t)}</div>" for h, t in cards if t))
    if s.get("do_first"):
        out.append("<div class='card'><b>Do first</b><ol class='steps'>" + "".join(f"<li>{e(x)}</li>" for x in s["do_first"]) + "</ol></div>")
    out.append("</div>")
    out.append('<div class="stats">' + "".join(f'<div class="stat"><span class="n">{counts[k]}</span><span class="l">{SEV[k]}</span></div>' for k in SEV)
               + f'<div class="stat"><span class="n">{len(builds)}</span><span class="l">Builds checked</span></div></div>')
    out.append('<div class="callout">All values in this report are masked: first four and last two characters only. Do not paste found values into tickets or chat.</div></header>')

    # Matrix
    if builds and findings:
        nav.append(("builds", "Builds"))
        out.append('<h2 id="builds">Which findings are in which build?</h2>')
        out.append("<ul class='mut'>" + "".join(f"<li><b>{e(b['name'])}.</b> {e(b.get('description', ''))}</li>" for b in builds) + "</ul>")
        out.append('<div class="legend">' + "".join(f"<span>{i} {t}</span>" for i, t in PRESENCE.values()) + "</div>")
        head = "".join(f"<th>{e(b['name'])}</th>" for b in builds)
        rows = []
        for f in findings:
            cells = []
            for b in builds:
                st = f.get("presence", {}).get(b["id"], "unchecked")
                icon, label = PRESENCE.get(st, PRESENCE["unchecked"])
                note = f.get("presence_note", {}).get(b["id"], "")
                cls = {"present": "p-present", "absent": "p-absent"}.get(st, "")
                cells.append(f'<td class="p {cls}">{icon} {e(label)}' + (f'<br><span class="mut">{e(note)}</span>' if note else "") + "</td>")
            rows.append(f'<tr><td><a href="#{e(f["id"])}">{e(f["id"])}</a></td><td>{e(f["title"])} <span class="tag t-{e(f.get("severity", "info"))}">{SEV.get(f.get("severity"), "Info")}</span></td>{"".join(cells)}<td>{e(f.get("owner", ""))}</td></tr>')
        out.append(f'<div class="tablewrap"><table><thead><tr><th>ID</th><th>Finding</th>{head}<th>Who acts</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>')
        if d.get("matrix_note"):
            out.append(f'<p class="mut">{e(d["matrix_note"])}</p>')

    # Layers
    if d.get("layers"):
        nav.append(("where", "Where"))
        out.append('<h2 id="where">Where does the exposure live?</h2><div class="layers">')
        for L in d["layers"]:
            chips = "".join(f'<a class="chip" href="#{e(i)}">{e(i)}</a>' for i in L.get("findings", []))
            out.append(f'<div class="card layer"><b>{e(L["name"])}</b><div class="reach">{e(L.get("reach", ""))}</div><p class="mut">{e(L.get("note", ""))}</p>{chips}</div>')
        out.append("</div>")
        if d.get("layers_conclusion"):
            out.append(f'<div class="callout">{e(d["layers_conclusion"])}</div>')

    # Findings
    nav.append(("findings", "Findings"))
    out.append('<h2 id="findings">What exactly did we find?</h2><p class="mut"><b>Secret</b> = must not be public. <b>Abuse risk</b> = public by design, but misuse is possible. <b>Info</b> = information only.</p>')
    out.append('<div class="tools"><input id="q" type="search" placeholder="Search findings" aria-label="Search findings">'
               '<span class="seg"><button data-f="all" aria-pressed="true">All</button> <button data-f="secret" aria-pressed="false">Secret</button> <button data-f="abuse-risk" aria-pressed="false">Abuse risk</button> <button data-f="info" aria-pressed="false">Info</button></span>'
               '<button id="expandAll">Expand all</button></div><p id="count" class="mut"></p>')
    for f in findings:
        sev = f.get("severity", "info")
        rows = "".join(f"<dt>{lab}</dt><dd>{paras(f[k])}</dd>" for k, lab in
                       [("what", "What"), ("evidence", "Evidence"), ("impact", "Impact"), ("open_point", "Open point"), ("fix", "Fix")] if f.get(k))
        rows += f"<dt>Owner</dt><dd>{e(f['owner'])}</dd>" if f.get("owner") else ""
        out.append(f'<details class="finding" id="{e(f["id"])}" data-sev="{e(sev)}"><summary><span class="fid">{e(f["id"])}</span>{e(f["title"])}'
                   f'<span class="tag t-{e(sev)}">{SEV.get(sev, "Info")}</span>' + (f'<span class="fsub">{e(f["subtitle"])}</span>' if f.get("subtitle") else "") + f"</summary><dl>{rows}</dl></details>")

    # Corrections
    if d.get("corrections"):
        nav.append(("corrections", "Corrections"))
        out.append('<h2 id="corrections">What changed since the first version?</h2><p class="mut">Corrections in one place.</p><ol class="steps">'
                   + "".join(f"<li><b>{e(c['title'])}</b> {e(c.get('text', ''))}</li>" for c in d["corrections"]) + "</ol>")

    # Method
    if d.get("method") or d.get("tools"):
        nav.append(("method", "Method"))
        out.append('<h2 id="method">How did we check?</h2>')
        if d.get("method"):
            out.append("<ol class='steps'>" + "".join(f"<li><b>{e(m['title'])}.</b> {e(m.get('text', ''))}</li>" for m in d["method"]) + "</ol>")
        if d.get("tools"):
            out.append('<h3>Tool results</h3><div class="tablewrap"><table><thead><tr><th>Tool</th><th>Target</th><th>Result</th></tr></thead><tbody>'
                       + "".join(f"<tr><td>{e(t['tool'])}</td><td>{e(t.get('target', ''))}</td><td>{e(t.get('result', ''))}</td></tr>" for t in d["tools"]) + "</tbody></table></div>")

    # Hardening
    if d.get("hardening"):
        h = d["hardening"]
        nav.append(("hardening", "Hardening"))
        out.append(f'<h2 id="hardening">{e(h.get("title", "Do the build hardening settings hide enough?"))}</h2>{paras(h.get("verdict", ""))}<ul>'
                   + "".join(f"<li>{e(p)}</li>" for p in h.get("points", [])) + "</ul>")

    # Next steps
    if d.get("next_steps"):
        nav.append(("next", "Next steps"))
        out.append('<h2 id="next">What happens next?</h2><p class="mut">Tick items to track progress. The ticks do not save.</p>')
        for n in d["next_steps"]:
            out.append(f'<div class="step"><span class="pri">{e(n.get("priority", ""))}</span><label><input type="checkbox"> {e(n["title"])}</label>'
                       f'<p class="mut">{e(n.get("text", ""))}</p><p class="mut">{e(", ".join(n.get("owners", [])))}</p></div>')

    # Scope
    sc = d.get("scope")
    if sc:
        nav.append(("scope", "Scope"))
        out.append('<h2 id="scope">Scope and limits</h2><div class="cols">'
                   f'<div><h3>Analysed</h3><ul>{"".join(f"<li>{e(x)}</li>" for x in sc.get("analysed", []))}</ul></div>'
                   f'<div><h3>Not analysed</h3><ul>{"".join(f"<li>{e(x)}</li>" for x in sc.get("not_analysed", []))}</ul></div></div>')

    if d.get("reproduce"):
        out.append(f'<h3>How to reproduce</h3><pre>{e(d["reproduce"])}</pre>')
    out.append(f'<footer>{e(d.get("footer", ""))}</footer>')

    navhtml = "".join(f'<a href="#{i}">{t}</a>' for i, t in nav) + '<button id="theme" aria-label="Toggle theme">Theme</button>'
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{e(d.get("title", "Mobile app exposure report"))}</title><style>{CSS}</style></head><body><nav style="display:flex;align-items:center">{navhtml}</nav>'
            f'<div class="wrap">{"".join(out)}</div><script>{JS}</script></body></html>')


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with open(sys.argv[1]) as fh:
        data = json.load(fh)
    check_masked(data)
    for f in data.get("findings", []):
        if "id" not in f or "title" not in f:
            sys.exit("error: every finding needs an id and a title.")
    with open(sys.argv[2], "w") as fh:
        fh.write(render(data))
    print(f"wrote {sys.argv[2]}")


if __name__ == "__main__":
    main()
