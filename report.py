"""Offline HTML report renderer for NetScaler Defensive Checker."""
from collections import Counter
from html import escape

LABELS = {
    'potentially_exposed': ('Potential exposure', 'risk'),
    'fixed_build': ('Fixed build', 'ok'),
    'precondition_not_observed': ('Prerequisite not observed', 'muted'),
    'configuration_unknown': ('Configuration unknown', 'warn'),
    'unknown_build': ('Build unknown', 'warn'),
}

REMEDIATION = {
    'CVE-2026-88771': 'Install the Citrix-recommended fixed build; prioritize assessment of potential compromise.',
    'CVE-2026-88772': 'Upgrade the appliance; verify DTLS configuration and exposure.',
    'CVE-2026-88773': 'Upgrade and review HTTP/SSL virtual server configurations.',
    'CVE-2026-88774': 'Upgrade; manually inspect policy expressions and bindings.',
    'CVE-2026-88775': 'Upgrade; review VPN and AAA virtual server exposure.',
    'CVE-2026-88776': 'Upgrade; inspect Oracle load-balancing vServers.',
    'CVE-2026-88777': 'Upgrade; verify non-HTTP L7 and NAT64/LSN features and bindings.',
    'CVE-2026-88778': 'Upgrade as applicable and enable Enhanced ISN Generation according to Citrix guidance.',
}

CSS = """
:root{color-scheme:light;--navy:#102b4e;--ink:#172b45;--line:#e3eaf2;--pale:#f5f8fc}
*{box-sizing:border-box}body{font-family:Arial,Helvetica,sans-serif;background:#eef2f7;color:var(--ink);margin:0}
main{max-width:1100px;margin:30px auto;background:white;padding:38px;border-radius:13px;box-shadow:0 8px 28px #20355012}
header{border-bottom:4px solid var(--navy);padding-bottom:18px}h1{color:var(--navy);margin:0 0 8px;font-size:29px}
h2{color:var(--navy);font-size:19px;margin-top:32px}.meta,.subtle{color:#62738b;font-size:13px}
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:24px 0}
.kpi{border:1px solid var(--line);border-radius:9px;padding:18px;background:var(--pale)}
.kpi .number{font-weight:700;font-size:28px;color:var(--navy)}.kpi .caption{font-size:12px;color:#546981}
table{width:100%;border-collapse:collapse;font-size:13px}th{background:var(--navy);color:white;text-align:left}
th,td{padding:12px 10px;border-bottom:1px solid var(--line);vertical-align:top}tr:nth-child(even){background:#f8fafc}
.status{display:inline-block;border-radius:14px;padding:5px 9px;font-size:11px;font-weight:700;white-space:nowrap}
.risk{color:#a11d29;background:#ffe9e9}.ok{color:#187246;background:#e1f6e9}.warn{color:#805a00;background:#fff2cf}
.muted{color:#526379;background:#eaf0f6}.notice{padding:15px 18px;border-left:4px solid var(--navy);background:var(--pale);font-size:13px;line-height:1.6}
li{margin:8px 0;line-height:1.45}footer{border-top:1px solid var(--line);padding-top:18px;margin-top:35px;font-size:12px;color:#617188}
a{color:#154d87;overflow-wrap:anywhere}@media print{body{background:white}main{box-shadow:none;padding:0;margin:0}.kpis{break-inside:avoid}tr{break-inside:avoid}}
@media(max-width:700px){main{margin:0;padding:18px}.kpis{grid-template-columns:repeat(2,1fr)}table{font-size:11px}th,td{padding:8px 5px}}
"""

def render_html(report):
    """Generate a standalone, escaped HTML document without external assets."""
    rows = report.get('results', [])
    counts = Counter(r.get('status', '') for r in rows)
    kpis = [
        ('Potential exposure', counts['potentially_exposed']),
        ('Fixed build', counts['fixed_build']),
        ('Needs review', counts['unknown_build'] + counts['configuration_unknown']),
        ('Not observed', counts['precondition_not_observed']),
    ]
    kpi_html = ''.join(f'<div class="kpi"><div class="number">{n}</div><div class="caption">{escape(label)}</div></div>' for label,n in kpis)
    table_rows = []
    for row in rows:
        status = row.get('status','')
        label, css = LABELS.get(status, ('Unknown', 'warn'))
        cve = escape(str(row.get('cve', '')))
        score = escape(str(row.get('cvss_v4', 'N/A')))
        observation = escape(str(row.get('observation', '')))
        recommendation = escape(REMEDIATION.get(row.get('cve',''), 'Review vendor advisory.'))
        table_rows.append(f'<tr><td><strong>{cve}</strong></td><td>{score}</td><td><span class="status {css}">{escape(label)}</span></td><td>{observation}</td><td>{recommendation}</td></tr>')
    limitations = ''.join(f'<li>{escape(str(x))}</li>' for x in report.get('limitations', []))
    edition = escape(str(report.get('edition') or 'Unknown'))
    build = escape(str(report.get('build') or 'Not provided'))
    build_status = escape(str(report.get('build_reason') or 'Unavailable'))
    generated = escape(str(report.get('generated_utc') or 'Unknown'))
    advisory = escape(str(report.get('advisory') or ''), quote=True)
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetScaler Defensive Checker | Grupo Oruss</title><style>{CSS}</style></head><body>
<main><header><h1>NetScaler Defensive Checker</h1><div>Executive exposure assessment | CVE-2026-88771 through CVE-2026-88778</div>
<p class="meta">Grupo Oruss · Defensive Security Research · Generated {generated} (UTC)</p></header>
<section class="kpis">{kpi_html}</section>
<h2>Appliance context</h2><p><strong>Build:</strong> {build} &nbsp; <strong>Edition:</strong> {edition}</p><div class="notice"><strong>Build evaluation:</strong> {build_status}.<br>Offline assessment only. A matching prerequisite does not confirm exploitability or compromise.</div>
<h2>Findings by CVE</h2><table><thead><tr><th>CVE</th><th>CVSS v4</th><th>Assessment</th><th>Observation</th><th>Recommended action</th></tr></thead><tbody>{''.join(table_rows)}</tbody></table>
<h2>Priorities</h2><div class="notice"><strong>Immediate attention:</strong> Citrix and CISA report active exploitation of CVE-2026-88771 and CVE-2026-88772. For potentially affected appliances, prioritize patching and a separate compromise investigation, preserving forensic evidence where appropriate.</div>
<h2>Method and limitations</h2><ul>{limitations}</ul>
<p class="subtle">Only aggregated match counts are included in the structured JSON output. This HTML does not reproduce raw configuration lines. Review the input offline.</p>
<footer>Independent security research by Grupo Oruss. Not affiliated with or endorsed by Citrix.<br>Official advisory: <a href="{advisory}" rel="noreferrer">{advisory}</a></footer>
</main></body></html>'''
