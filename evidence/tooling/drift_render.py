# Drift Sentinel — drift_render.py v2 (dual-mode)
# Location in repo (REQUIRED): evidence/tooling/drift_render.py
# Reads /harness/.agent/output/drift-report.json (dual-mode schema) and optional drift-notes.json
# ({"summary": "...", "notes": {"DR-01": "...", "AB-01": "..."}}), writes Drift_Report.html.
# Backward compatible: if report has no 'authorized' block, renders rolling-only.
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

rolling = r.get('rolling', {
    'verdict': r.get('verdict'), 'max_severity': r.get('max_severity'), 'counts': r.get('counts', {}),
    'prior_captured_at': r.get('prior_captured_at'), 'prior_run_sequence': r.get('prior_run_sequence'),
    'prior_yaml_sha256': r.get('prior_yaml_sha256'), 'prior_templates': r.get('prior_templates', {}),
    'findings': r.get('findings', []),
})
authorized = r.get('authorized')

SEV_COLORS = {'critical': '#ef4444', 'high': '#f97316', 'medium': '#f59e0b', 'info': '#38bdf8'}

VERDICT_STYLE = {
    'BASELINE': ('#38bdf8', 'BASELINE ESTABLISHED'),
    'NO_DRIFT': ('#22c55e', 'NO DRIFT \u2014 VERIFIED UNCHANGED'),
    'COMPLIANT': ('#22c55e', 'COMPLIANT \u2014 MATCHES AUTHORIZED BASELINE'),
    'DRIFT': ('#ef4444' if r.get('max_severity') == 'critical' else '#f59e0b', 'DRIFT DETECTED'),
    'DEVIATION': ('#ef4444' if r.get('max_severity') == 'critical' else '#f59e0b',
                  'DEVIATION FROM AUTHORIZED BASELINE'),
}
vcolor, vlabel = VERDICT_STYLE.get(r['verdict'], ('#94a3b8', r['verdict']))


def esc(x):
    return html.escape(str(x)) if x is not None else ''


def badge(sev):
    c = SEV_COLORS.get(sev, '#94a3b8')
    return (f'<span style="background:{c}22;color:{c};border:1px solid {c}55;border-radius:100px;'
            f'padding:2px 10px;font-size:10px;font-weight:700;letter-spacing:.06em;'
            f'text-transform:uppercase;white-space:nowrap">{sev}</span>')


def findings_table(findings):
    rows = ''
    for f in findings:
        note = notes.get('notes', {}).get(f['id'], '')
        note_html = f'<div style="color:#7dd3fc;font-size:11px;margin-top:4px">{esc(note)}</div>' if note else ''
        rows += (
            f'<tr><td class="mono dim">{esc(f["id"])}</td><td>{badge(f["severity"])}</td>'
            f'<td class="cat">{esc(f["category"].replace("_", " "))}</td>'
            f'<td class="mono">{esc(f["location"])}</td>'
            f'<td><span class="mono before">{esc(f["before"])}</span><span class="arrow">\u2192</span>'
            f'<span class="mono after">{esc(f["after"])}</span>'
            f'<div class="detail">{esc(f["detail"])}</div>{note_html}</td></tr>')
    if not rows:
        rows = ('<tr><td colspan="5" style="text-align:center;color:#475569;padding:20px">'
                'No findings.</td></tr>')
    return ('<div class="wrap"><table><thead><tr><th>ID</th><th>Severity</th><th>Category</th>'
            '<th>Location</th><th>Change</th></tr></thead><tbody>' + rows + '</tbody></table></div>')


def stat_strip(counts):
    cards = ''
    for sev in ('critical', 'high', 'medium', 'info'):
        c = SEV_COLORS[sev]
        n = counts.get(sev, 0)
        dim = '' if n else 'opacity:.35;'
        cards += (f'<div class="stat" style="{dim}border-bottom:3px solid {c}">'
                  f'<div class="num" style="color:{c}">{n}</div><div class="lbl">{sev}</div></div>')
    return f'<div class="stats">{cards}</div>'


authorized_html = ''
if authorized is not None:
    av = authorized['verdict']
    am = authorized.get('authorization', {}) or {}
    acolor = {'COMPLIANT': '#22c55e',
              'DEVIATION': '#ef4444' if authorized['max_severity'] == 'critical' else '#f59e0b',
              'UNAUTHORIZED': '#f59e0b'}.get(av, '#94a3b8')
    if av == 'UNAUTHORIZED':
        auth_banner = ('<div class="auth-warn">No authorized baseline is pinned for this pipeline. '
                       'Compliance comparison is unavailable until an approved baseline is captured '
                       'via the approve-baseline action. Until then, only rolling drift is monitored.</div>')
        auth_body = ''
    else:
        meta_bits = []
        for k, lbl in [('ato_id', 'ATO / Authorization'), ('ato_date', 'Authorized On'),
                       ('control_set', 'Control Set'), ('approved_by', 'Approving Official'),
                       ('change_ticket', 'Change Ticket')]:
            if am.get(k):
                meta_bits.append(f'<span class="auth-meta-item"><b>{lbl}:</b> {esc(am[k])}</span>')
        baseline_line = (f'Baseline captured {esc(authorized.get("baseline_captured_at"))} · '
                         f'sha {esc((authorized.get("baseline_yaml_sha256") or "")[:12])}')
        auth_banner = (f'<div class="auth-meta">{"".join(meta_bits) or "<span class=auth-meta-item>Authorization metadata not recorded</span>"}'
                       f'<span class="auth-meta-item dim">{baseline_line}</span></div>')
        if av == 'COMPLIANT':
            auth_body = ('<div class="ok-line">Pipeline configuration is byte-for-byte identical to the '
                         'authorized baseline. No deviation from the approved control state.</div>')
        else:
            auth_body = stat_strip(authorized['counts']) + findings_table(authorized['findings'])
    authorized_html = f'''
<div class="section authsec">
<div class="section-head" style="border-left-color:{acolor}">
<h2>Authorized Baseline Compliance</h2>
<span class="vpill" style="background:{acolor}1a;color:{acolor};border-color:{acolor}55">{esc(av)}</span>
</div>
{auth_banner}
{auth_body}
</div>'''

rv = rolling['verdict']
rcolor = {'BASELINE': '#38bdf8', 'NO_DRIFT': '#22c55e',
          'DRIFT': '#ef4444' if rolling['max_severity'] == 'critical' else '#f59e0b'}.get(rv, '#94a3b8')
if rv == 'BASELINE':
    rolling_body = (f'<div class="ok-line">First run for this pipeline. Monitoring state established over '
                    f'{r["monitored_stages"]} stages, {r["monitored_steps"]} steps, and '
                    f'{len(r["templates"])} template references. Future runs compare against this snapshot.</div>')
elif rv == 'NO_DRIFT':
    rolling_body = (f'<div class="ok-line">Pipeline YAML verified identical to Run #'
                    f'{esc(rolling.get("prior_run_sequence"))} ({esc(rolling.get("prior_captured_at"))}). '
                    f'No structural changes since the last run.</div>')
else:
    rolling_body = stat_strip(rolling['counts']) + findings_table(rolling['findings'])
rolling_prior = ''
if rolling.get('prior_yaml_sha256'):
    rolling_prior = (f'<div class="meta-line">Compared to Run #{esc(rolling.get("prior_run_sequence"))} · '
                     f'{esc(rolling.get("prior_captured_at"))} · sha {esc(rolling["prior_yaml_sha256"][:12])}</div>')

rolling_html = f'''
<div class="section">
<div class="section-head" style="border-left-color:{rcolor}">
<h2>Rolling Drift (Since Last Run)</h2>
<span class="vpill" style="background:{rcolor}1a;color:{rcolor};border-color:{rcolor}55">{esc(rv)}</span>
</div>
{rolling_prior}
{rolling_body}
</div>'''

tpl_rows = ''
ref_templates = (authorized.get('baseline_templates') if authorized and authorized.get('baseline_yaml_sha256')
                 else rolling.get('prior_templates', {})) or {}
ref_label = 'Authorized' if (authorized and authorized.get('baseline_yaml_sha256')) else 'Previous'
all_refs = sorted(set(list(r['templates'].keys()) + list(ref_templates.keys())))
for ref in all_refs:
    prev = ref_templates.get(ref, '\u2014')
    cur = r['templates'].get(ref, '\u2014')
    changed = prev != cur and prev != '\u2014'
    status = ('<span style="color:#f59e0b;font-weight:700">CHANGED</span>' if changed
              else '<span style="color:#22c55e">stable</span>' if ref_templates
              else '<span style="color:#38bdf8">recorded</span>')
    tpl_rows += (f'<tr><td class="mono">{esc(ref)}</td><td class="mono dim">{esc(prev)}</td>'
                 f'<td class="mono">{esc(cur)}</td><td>{status}</td></tr>')
if not tpl_rows:
    tpl_rows = '<tr><td colspan="4" style="text-align:center;color:#475569;padding:16px">No template references.</td></tr>'

summary = notes.get('summary') or ''
summary_html = f'<div class="summary" style="border-left-color:{vcolor}">{esc(summary)}</div>' if summary else ''

html_out = f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Drift Sentinel \u2014 {esc(r['pipeline_name'])}</title>
<style>
* {{ box-sizing:border-box; margin:0; padding:0; }}
body {{ background:#0f172a; color:#e2e8f0; font-family:system-ui,-apple-system,'Segoe UI',sans-serif; font-size:14px; line-height:1.5; }}
.page {{ max-width:1100px; margin:0 auto; padding:28px 20px; }}
.header {{ background:linear-gradient(135deg,#1e293b 0%,#0f172a 70%); border:1px solid #334155; border-radius:12px; padding:26px 30px; margin-bottom:20px; }}
.verdict {{ display:inline-block; background:{vcolor}1a; color:{vcolor}; border:1px solid {vcolor}55; border-radius:100px; padding:5px 18px; font-size:12px; font-weight:800; letter-spacing:.12em; margin-bottom:12px; }}
h1 {{ font-size:1.5rem; font-weight:800; color:#f1f5f9; }}
h1 span {{ color:#38bdf8; }}
.meta-line {{ color:#64748b; font-size:12px; margin-top:6px; font-family:'SF Mono',monospace; }}
.summary {{ background:rgba(56,189,248,0.06); border-left:3px solid {vcolor}; border-radius:6px; padding:12px 16px; margin-top:14px; color:#cbd5e1; font-size:13px; }}
.stats {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:14px 0; }}
.stat {{ background:#1e293b; border:1px solid #334155; border-radius:10px; padding:14px 18px; }}
.num {{ font-size:2rem; font-weight:800; line-height:1; }}
.lbl {{ font-size:10px; font-weight:700; letter-spacing:.1em; text-transform:uppercase; color:#64748b; margin-top:4px; }}
.section {{ margin-bottom:24px; }}
.authsec {{ background:rgba(34,197,94,0.03); border:1px solid #334155; border-radius:12px; padding:16px 18px; }}
.section-head {{ display:flex; align-items:center; justify-content:space-between; gap:10px; margin:6px 0 12px; padding-left:10px; border-left:3px solid #38bdf8; }}
.section-head h2 {{ font-size:.85rem; font-weight:700; letter-spacing:.08em; text-transform:uppercase; color:#94a3b8; }}
.vpill {{ border:1px solid; border-radius:100px; padding:3px 14px; font-size:11px; font-weight:800; letter-spacing:.1em; }}
.auth-meta {{ display:flex; flex-wrap:wrap; gap:14px; background:#0f172a; border:1px solid #334155; border-radius:8px; padding:10px 14px; margin-bottom:12px; font-size:12px; }}
.auth-meta-item b {{ color:#94a3b8; font-weight:600; }}
.auth-meta-item.dim {{ color:#64748b; font-family:'SF Mono',monospace; }}
.auth-warn {{ background:rgba(245,158,11,0.08); border:1px solid rgba(245,158,11,0.3); border-radius:8px; padding:12px 16px; color:#fbbf24; font-size:13px; }}
.ok-line {{ background:rgba(34,197,94,0.06); border:1px solid rgba(34,197,94,0.25); border-radius:8px; padding:12px 16px; color:#86efac; font-size:13px; }}
.wrap {{ background:#1e293b; border:1px solid #334155; border-radius:10px; overflow:hidden; }}
table {{ width:100%; border-collapse:collapse; }}
thead tr {{ background:#0f172a; border-bottom:2px solid #334155; }}
th {{ padding:9px 12px; text-align:left; font-size:10px; font-weight:700; letter-spacing:.1em; text-transform:uppercase; color:#475569; }}
td {{ padding:10px 12px; font-size:12px; border-bottom:1px solid #0f172a; vertical-align:top; }}
.mono {{ font-family:'SF Mono','Fira Code',monospace; font-size:11px; }}
.dim {{ color:#64748b; }}
.cat {{ font-weight:600; color:#cbd5e1; white-space:nowrap; }}
.before {{ color:#f87171; }} .after {{ color:#4ade80; }} .arrow {{ color:#475569; margin:0 8px; }}
.detail {{ color:#94a3b8; font-size:11px; margin-top:4px; }}
.footer {{ text-align:center; color:#475569; font-size:11px; margin-top:24px; padding:12px; border:1px solid #334155; border-radius:8px; background:#1e293b; }}
</style></head><body><div class="page">
<div class="header">
<div class="verdict">\u25c9 {vlabel}</div>
<h1>PIPELINE DRIFT <span>SENTINEL</span></h1>
<div class="meta-line">{esc(r['pipeline_name'])} ({esc(r['pipeline_id'])}) · Run #{esc(r['run_sequence'])} · Execution {esc(r['execution_id'])}</div>
<div class="meta-line">Captured {esc(r['captured_at'])} · YAML sha {esc(r['yaml_sha256'][:12])} · Monitoring {r['monitored_stages']} stages / {r['monitored_steps']} steps / {len(r['templates'])} templates</div>
{summary_html}
</div>
{authorized_html}
{rolling_html}
<div class="section"><div class="section-head"><h2>Template References (vs {ref_label})</h2></div>
<div class="wrap"><table><thead><tr><th>Template</th><th>{ref_label} Version</th><th>Current Version</th><th>Status</th></tr></thead>
<tbody>{tpl_rows}</tbody></table></div></div>
<div class="footer"><strong style="color:#64748b">Generated by Pipeline Drift Sentinel</strong> &nbsp;|&nbsp; Dual-mode: authorized-baseline compliance + rolling drift &nbsp;|&nbsp; This agent's own step is part of the monitored surface &nbsp;|&nbsp; {esc(r['pipe_key'])}</div>
</div></body></html>'''

open(f'{BASE}/Drift_Report.html', 'w').write(html_out)
print(f"Rendered {len(html_out)} bytes")
