# Drift Sentinel — drift_render.py v1
# Location in repo (REQUIRED): evidence/tooling/drift_render.py
# Reads /harness/.agent/output/drift-report.json and optional drift-notes.json
# ({"summary": "...", "notes": {"DR-01": "one-liner", ...}}), writes Drift_Report.html.
# The agent never modifies this file.

import html
import json
import os

BASE = '/harness/.agent/output'
r = json.load(open(f'{BASE}/drift-report.json'))
notes = {'summary': '', 'notes': {}}
if os.path.exists(f'{BASE}/drift-notes.json'):
    try:
        notes = json.load(open(f'{BASE}/drift-notes.json'))
    except Exception:
        pass

VERDICT_STYLE = {
    'BASELINE': ('#38bdf8', 'BASELINE ESTABLISHED'),
    'NO_DRIFT': ('#22c55e', 'NO DRIFT \u2014 VERIFIED UNCHANGED'),
    'DRIFT': ('#ef4444' if r['max_severity'] == 'critical' else '#f59e0b', 'DRIFT DETECTED'),
}
vcolor, vlabel = VERDICT_STYLE.get(r['verdict'], ('#94a3b8', r['verdict']))

default_summary = {
    'BASELINE': f"First run for this pipeline. Monitoring state established over {r['monitored_stages']} stages, "
                f"{r['monitored_steps']} steps, and {len(r['templates'])} template references. "
                f"Future runs compare against this snapshot.",
    'NO_DRIFT': f"Pipeline YAML hash verified identical to Run #{r.get('prior_run_sequence')} "
                f"({r.get('prior_captured_at')}). No structural changes since the last run.",
    'DRIFT': f"{sum(r['counts'].values())} change(s) detected since Run #{r.get('prior_run_sequence')} "
             f"({r.get('prior_captured_at')}). Highest severity: {r['max_severity'].upper()}.",
}
summary = notes.get('summary') or default_summary.get(r['verdict'], '')

SEV_COLORS = {'critical': '#ef4444', 'high': '#f97316', 'medium': '#f59e0b', 'info': '#38bdf8'}


def badge(sev):
    c = SEV_COLORS.get(sev, '#94a3b8')
    return (f'<span style="background:{c}22;color:{c};border:1px solid {c}55;border-radius:100px;'
            f'padding:2px 10px;font-size:10px;font-weight:700;letter-spacing:.06em;'
            f'text-transform:uppercase;white-space:nowrap">{sev}</span>')


def esc(x):
    return html.escape(str(x)) if x is not None else ''


finding_rows = ''
for f in r['findings']:
    note = notes.get('notes', {}).get(f['id'], '')
    note_html = f'<div style="color:#7dd3fc;font-size:11px;margin-top:4px">{esc(note)}</div>' if note else ''
    finding_rows += (
        f'<tr><td class="mono dim">{f["id"]}</td><td>{badge(f["severity"])}</td>'
        f'<td class="cat">{esc(f["category"].replace("_", " "))}</td>'
        f'<td class="mono">{esc(f["location"])}</td>'
        f'<td><span class="mono before">{esc(f["before"])}</span><span class="arrow">\u2192</span>'
        f'<span class="mono after">{esc(f["after"])}</span>'
        f'<div class="detail">{esc(f["detail"])}</div>{note_html}</td></tr>')
if not finding_rows:
    finding_rows = ('<tr><td colspan="5" style="text-align:center;color:#475569;padding:24px">'
                    'No findings for this run.</td></tr>')

tpl_rows = ''
all_refs = sorted(set(list(r['templates'].keys()) + list(r.get('prior_templates', {}).keys())))
for ref in all_refs:
    prev = r.get('prior_templates', {}).get(ref, '\u2014')
    cur = r['templates'].get(ref, '\u2014')
    changed = prev != cur and r['verdict'] != 'BASELINE'
    status = ('<span style="color:#f59e0b;font-weight:700">CHANGED</span>' if changed
              else '<span style="color:#22c55e">stable</span>' if r['verdict'] != 'BASELINE'
              else '<span style="color:#38bdf8">recorded</span>')
    tpl_rows += (f'<tr><td class="mono">{esc(ref)}</td><td class="mono dim">{esc(prev)}</td>'
                 f'<td class="mono">{esc(cur)}</td><td>{status}</td></tr>')
if not tpl_rows:
    tpl_rows = '<tr><td colspan="4" style="text-align:center;color:#475569;padding:16px">No template references.</td></tr>'

stat_cards = ''
for sev in ('critical', 'high', 'medium', 'info'):
    c = SEV_COLORS[sev]
    n = r['counts'].get(sev, 0)
    dim = '' if n else 'opacity:.35;'
    stat_cards += (f'<div class="stat" style="{dim}border-bottom:3px solid {c}">'
                   f'<div class="num" style="color:{c}">{n}</div>'
                   f'<div class="lbl">{sev}</div></div>')

prior_line = ''
if r.get('prior_yaml_sha256'):
    prior_line = (f'<div class="meta-line">Compared to: Run #{esc(r.get("prior_run_sequence"))} · '
                  f'{esc(r.get("prior_captured_at"))} · sha {esc(r["prior_yaml_sha256"][:12])}</div>')

html_out = f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Drift Sentinel \u2014 {esc(r['pipeline_name'])}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background:#0f172a; color:#e2e8f0; font-family:system-ui,-apple-system,'Segoe UI',sans-serif; font-size:14px; line-height:1.5; }}
.page {{ max-width:1100px; margin:0 auto; padding:28px 20px; }}
.header {{ background:linear-gradient(135deg,#1e293b 0%,#0f172a 70%); border:1px solid #334155; border-radius:12px; padding:26px 30px; margin-bottom:20px; }}
.verdict {{ display:inline-block; background:{vcolor}1a; color:{vcolor}; border:1px solid {vcolor}55; border-radius:100px; padding:5px 18px; font-size:12px; font-weight:800; letter-spacing:.12em; margin-bottom:12px; }}
h1 {{ font-size:1.5rem; font-weight:800; color:#f1f5f9; }}
h1 span {{ color:#38bdf8; }}
.meta-line {{ color:#64748b; font-size:12px; margin-top:6px; font-family:'SF Mono',monospace; }}
.summary {{ background:rgba(56,189,248,0.06); border-left:3px solid {vcolor}; border-radius:6px; padding:12px 16px; margin-top:14px; color:#cbd5e1; font-size:13px; }}
.stats {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:20px; }}
.stat {{ background:#1e293b; border:1px solid #334155; border-radius:10px; padding:14px 18px; }}
.num {{ font-size:2rem; font-weight:800; line-height:1; }}
.lbl {{ font-size:10px; font-weight:700; letter-spacing:.1em; text-transform:uppercase; color:#64748b; margin-top:4px; }}
.section h2 {{ font-size:.85rem; font-weight:700; letter-spacing:.08em; text-transform:uppercase; color:#94a3b8; margin:18px 0 10px; padding-left:10px; border-left:3px solid #38bdf8; }}
.wrap {{ background:#1e293b; border:1px solid #334155; border-radius:10px; overflow:hidden; }}
table {{ width:100%; border-collapse:collapse; }}
thead tr {{ background:#0f172a; border-bottom:2px solid #334155; }}
th {{ padding:9px 12px; text-align:left; font-size:10px; font-weight:700; letter-spacing:.1em; text-transform:uppercase; color:#475569; }}
td {{ padding:10px 12px; font-size:12px; border-bottom:1px solid #0f172a; vertical-align:top; }}
.mono {{ font-family:'SF Mono','Fira Code',monospace; font-size:11px; }}
.dim {{ color:#64748b; }}
.cat {{ font-weight:600; color:#cbd5e1; white-space:nowrap; }}
.before {{ color:#f87171; }}
.after {{ color:#4ade80; }}
.arrow {{ color:#475569; margin:0 8px; }}
.detail {{ color:#94a3b8; font-size:11px; margin-top:4px; }}
.footer {{ text-align:center; color:#475569; font-size:11px; margin-top:24px; padding:12px; border:1px solid #334155; border-radius:8px; background:#1e293b; }}
</style></head><body><div class="page">
<div class="header">
<div class="verdict">\u25c9 {vlabel}</div>
<h1>PIPELINE DRIFT <span>SENTINEL</span></h1>
<div class="meta-line">{esc(r['pipeline_name'])} ({esc(r['pipeline_id'])}) · Run #{esc(r['run_sequence'])} · Execution {esc(r['execution_id'])}</div>
<div class="meta-line">Captured: {esc(r['captured_at'])} · Branch: <span style="color:#a78bfa">{esc(r.get('branch','unknown'))}</span> · YAML sha {esc(r['yaml_sha256'][:12])} · Monitoring {r['monitored_stages']} stages / {r['monitored_steps']} steps / {len(r['templates'])} templates</div>
{prior_line}
<div class="summary">{esc(summary)}</div>
</div>
<div class="stats">{stat_cards}</div>
<div class="section"><h2>Findings</h2>
<div class="wrap"><table><thead><tr><th>ID</th><th>Severity</th><th>Category</th><th>Location</th><th>Change</th></tr></thead>
<tbody>{finding_rows}</tbody></table></div></div>
<div class="section"><h2>Template References</h2>
<div class="wrap"><table><thead><tr><th>Template</th><th>Previous Version</th><th>Current Version</th><th>Status</th></tr></thead>
<tbody>{tpl_rows}</tbody></table></div></div>
<div class="footer"><strong style="color:#64748b">Generated by Pipeline Drift Sentinel</strong> &nbsp;|&nbsp; Tamper-evident: this agent's own step is part of the monitored surface &nbsp;|&nbsp; {esc(r['pipe_key'])} &nbsp;|&nbsp; {esc(r['captured_at'])}</div>
</div></body></html>'''

open(f'{BASE}/Drift_Report.html', 'w').write(html_out)
print(f"Rendered {len(html_out)} bytes")
