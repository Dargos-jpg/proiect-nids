from __future__ import annotations

from datetime import datetime
from pathlib import Path

from nids.storage.event_store import StoredEvent

_SEVERITY_COLOR = {
    "ridicata": "#f14c4c",
    "medie": "#dcdcaa",
    "scazuta": "#4ec9b0",
}


def generate_html_report(events: list[StoredEvent], title: str = "Raport NIDS") -> str:
    """raport HTML de sine statator (fara dependinte externe, fara CSS/JS
    incarcat din alta parte) - vezi CONTEXT-nids.md, "raport exportabil
    (PDF/HTML) pentru o perioada data" """
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows_html = "\n".join(_row_html(e) for e in events) or (
        '<tr><td colspan="5">niciun eveniment</td></tr>'
    )

    counts = {"ridicata": 0, "medie": 0, "scazuta": 0}
    for event in events:
        if event.severity in counts:
            counts[event.severity] += 1

    return f"""<!doctype html>
<html lang="ro">
<head>
<meta charset="utf-8">
<title>{_escape(title)}</title>
<style>
body {{ font-family: -apple-system, "Segoe UI", sans-serif; background:#1e1e1e;
        color:#cccccc; margin: 2rem; }}
h1 {{ color: #ffffff; }}
.meta {{ color: #8a8a8a; margin-bottom: 1.5rem; }}
.summary {{ display:flex; gap:1rem; margin-bottom:1.5rem; }}
.stat {{ background:#252526; border:1px solid #3c3c3c; border-radius:6px;
         padding:0.75rem 1.25rem; }}
.stat .n {{ font-size:1.5rem; font-weight:bold; }}
table {{ width:100%; border-collapse: collapse; }}
th, td {{ text-align:left; padding:6px 10px; border-bottom:1px solid #3c3c3c; font-size:13px; }}
th {{ background:#2d2d2d; color:#cccccc; }}
tr:hover {{ background:#252526; }}
</style>
</head>
<body>
<h1>{_escape(title)}</h1>
<div class="meta">generat la {generated_at} &middot; {len(events)} evenimente</div>
<div class="summary">
<div class="stat"><div class="n" style="color:{_SEVERITY_COLOR['ridicata']}">{counts['ridicata']}</div>severitate ridicata</div>
<div class="stat"><div class="n" style="color:{_SEVERITY_COLOR['medie']}">{counts['medie']}</div>severitate medie</div>
<div class="stat"><div class="n" style="color:{_SEVERITY_COLOR['scazuta']}">{counts['scazuta']}</div>severitate scazuta</div>
</div>
<table>
<thead><tr><th>timp</th><th>tip</th><th>sursa</th><th>severitate</th><th>descriere</th></tr></thead>
<tbody>
{rows_html}
</tbody>
</table>
</body>
</html>
"""


def save_report(events: list[StoredEvent], path: Path, title: str = "Raport NIDS") -> None:
    path.write_text(generate_html_report(events, title=title), encoding="utf-8")


def _row_html(event: StoredEvent) -> str:
    color = _SEVERITY_COLOR.get(event.severity, "#cccccc")
    return (
        f"<tr><td>{_escape(event.timestamp)}</td><td>{_escape(event.event_type)}</td>"
        f"<td>{_escape(event.source_ip)}</td>"
        f'<td style="color:{color}">{_escape(event.severity)}</td>'
        f"<td>{_escape(event.description)}</td></tr>"
    )


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
