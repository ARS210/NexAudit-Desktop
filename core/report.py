"""
core/report.py

Generates a self-contained HTML audit report from parsed scan results,
tagged with engagement metadata (scope, authorization reference, dates)
so every report is traceable to a documented authorization.
"""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from core.parser import AccessPoint, Station
from version import APP_NAME, VERSION, AUTHOR, DEVELOPERS, LEGAL_NOTICE

_STYLE = """
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0; background: #0f1115; color: #e6e6e6; }
.wrap { max-width: 980px; margin: 0 auto; padding: 32px; }
h1 { font-size: 26px; margin-bottom: 4px; }
.subtitle { color: #9aa4b2; margin-bottom: 24px; }
.card { background: #171a21; border: 1px solid #262b36; border-radius: 10px; padding: 20px; margin-bottom: 20px; }
.card h2 { margin-top: 0; font-size: 16px; color: #7dd3fc; text-transform: uppercase; letter-spacing: .04em; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #262b36; }
th { color: #9aa4b2; font-weight: 600; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }
.badge-open { background: #451a1a; color: #fca5a5; }
.badge-secured { background: #14301f; color: #86efac; }
.meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px 24px; font-size: 14px; }
.meta-grid dt { color: #9aa4b2; }
.meta-grid dd { margin: 0 0 8px 0; }
.legal { font-size: 12px; color: #6b7280; margin-top: 30px; border-top: 1px solid #262b36; padding-top: 16px; }
footer { text-align: center; color: #4b5563; font-size: 12px; margin-top: 24px; }
"""


def _privacy_badge(ap: AccessPoint) -> str:
    if ap.is_open:
        return '<span class="badge badge-open">OPEN</span>'
    return f'<span class="badge badge-secured">{html.escape(ap.privacy or "SECURED")}</span>'


def generate_html_report(
    engagement: dict,
    access_points: list[AccessPoint],
    stations: list[Station],
    output_path: Path,
) -> Path:
    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    open_count = sum(1 for ap in access_points if ap.is_open)

    ap_rows = "\n".join(
        f"""<tr>
            <td>{html.escape(ap.essid or '(hidden)')}</td>
            <td>{html.escape(ap.bssid)}</td>
            <td>{ap.channel}</td>
            <td>{ap.power}</td>
            <td>{_privacy_badge(ap)}</td>
            <td>{html.escape(ap.cipher)}</td>
            <td>{html.escape(ap.last_seen)}</td>
        </tr>"""
        for ap in access_points
    )

    station_rows = "\n".join(
        f"""<tr>
            <td>{html.escape(s.mac)}</td>
            <td>{html.escape(s.associated_bssid) or '(unassociated)'}</td>
            <td>{s.power}</td>
            <td>{s.packets}</td>
            <td>{html.escape(s.last_seen)}</td>
        </tr>"""
        for s in stations
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{APP_NAME} Audit Report — {html.escape(engagement.get('name', ''))}</title>
<style>{_STYLE}</style>
</head>
<body>
<div class="wrap">
    <h1>{APP_NAME} Wireless Assessment Report</h1>
    <div class="subtitle">Generated {generated_at} &middot; {APP_NAME} {VERSION}</div>

    <div class="card">
        <h2>Engagement Details</h2>
        <dl class="meta-grid">
            <dt>Engagement Name</dt><dd>{html.escape(engagement.get('name',''))}</dd>
            <dt>Client</dt><dd>{html.escape(engagement.get('client','') or '—')}</dd>
            <dt>Authorized By</dt><dd>{html.escape(engagement.get('authorized_by',''))}</dd>
            <dt>Authorization Reference</dt><dd>{html.escape(engagement.get('authorization_ref','') or '—')}</dd>
            <dt>Start Date</dt><dd>{html.escape(engagement.get('start_date',''))}</dd>
            <dt>End Date</dt><dd>{html.escape(engagement.get('end_date','') or '—')}</dd>
        </dl>
    </div>

    <div class="card">
        <h2>Summary</h2>
        <dl class="meta-grid">
            <dt>Access Points Observed</dt><dd>{len(access_points)}</dd>
            <dt>Open / Unencrypted APs</dt><dd>{open_count}</dd>
            <dt>Client Stations Observed</dt><dd>{len(stations)}</dd>
        </dl>
    </div>

    <div class="card">
        <h2>Access Points</h2>
        <table>
            <thead><tr>
                <th>ESSID</th><th>BSSID</th><th>Ch</th><th>Power</th>
                <th>Privacy</th><th>Cipher</th><th>Last Seen</th>
            </tr></thead>
            <tbody>{ap_rows or '<tr><td colspan="7">No access points recorded.</td></tr>'}</tbody>
        </table>
    </div>

    <div class="card">
        <h2>Client Stations</h2>
        <table>
            <thead><tr>
                <th>MAC</th><th>Associated BSSID</th><th>Power</th><th>Packets</th><th>Last Seen</th>
            </tr></thead>
            <tbody>{station_rows or '<tr><td colspan="5">No client stations recorded.</td></tr>'}</tbody>
        </table>
    </div>

    <div class="legal">{html.escape(LEGAL_NOTICE)}</div>
    <footer>{APP_NAME} {VERSION} &middot; {AUTHOR} &middot; Developed by {DEVELOPERS}</footer>
</div>
</body>
</html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(doc, encoding="utf-8")
    return output_path
