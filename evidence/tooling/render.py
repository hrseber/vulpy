# AGR Renderer v2 — Locked HTML renderer with DELTA merge + count normalization
# Location in repo (REQUIRED): evidence/tooling/render.py  (overwrites v1)
# Behavior:
#   1. If agr-data-delta.json AND /tmp/baseline.json exist (DELTA mode), merge the
#      cached baseline Pass 1 content with the fresh delta fields, and materialize
#      the merged result to agr-data.json for downstream consumers.
#   2. Recompute passed/failed/unable/na and score_pct from the checks array in
#      EVERY mode, enforcing the scoring rule deterministically (N/A and UNABLE
#      excluded from the denominator). Model-typed counts are overwritten.
#   3. Render the locked HTML template. The agent never modifies this file.
# Backward compatible: with no delta file present, behaves like v1 plus normalization.

import json
import os

BASE = '/harness/.agent/output'
DELTA_PATH = f'{BASE}/agr-data-delta.json'
DATA_PATH = f'{BASE}/agr-data.json'
BASELINE_PATH = '/tmp/baseline.json'

BASELINE_FIELDS_FROM_PASS1 = ['passed_sub', 'failed_sub']


def load_data():
    if os.path.exists(DELTA_PATH) and os.path.exists(BASELINE_PATH):
        delta = json.load(open(DELTA_PATH))
        b = json.load(open(BASELINE_PATH))
        p = b['pass1']
        d = dict(delta)
        d['checks'] = p['checks']
        for k in BASELINE_FIELDS_FROM_PASS1:
            d[k] = p.get(k, '')
        d['policies'] = b['policies']
        d['remediations'] = b['remediations']
        d['nist_800_53'] = b['nist_800_53']
        d['coverage_covered'] = b['coverage_covered']
        d['coverage_total'] = b['coverage_total']
        print(f"DELTA merge: {len(p['checks'])} checks, {len(b['policies'])} policies, "
              f"{len(b['remediations'])} remediations reused from baseline {b.get('baseline_timestamp','')}")
        return d
    return json.load(open(DATA_PATH))


def normalize_counts(d):
    counts = {'pass': 0, 'fail': 0, 'unable': 0, 'na': 0}
    for ch in d.get('checks', []):
        s = ch.get('status', '')
        if s in counts:
            counts[s] += 1
    d['passed'] = counts['pass']
    d['failed'] = counts['fail']
    d['unable'] = counts['unable']
    d['na'] = counts['na']
    applicable = len(d.get('checks', [])) - counts['na'] - counts['unable']
    d['score_pct'] = f"{round(counts['pass'] / applicable * 100)}%" if applicable > 0 else "N/A"
    return d


d = normalize_counts(load_data())
json.dump(d, open(DATA_PATH, 'w'), ensure_ascii=False)

STATUS_LABELS = {"pass": "\u2713 PASS", "fail": "\u2715 FAIL", "na": "\u2014 N/A", "unable": "\u26a0 UNABLE"}
SEV_LABELS = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "na": "N/A", "unable": "UNABLE"}


def ctrl_ids(ids):
    return '<div class="ctrl-ids">' + "".join(f'<span class="ctrl-id">{i}</span>' for i in ids) + '</div>' if ids else '<span style="color:#475569;font-size:11px">N/A</span>'


def check_row(c):
    row_style = ' style="background: rgba(239,68,68,0.04);"' if c["severity"] == "critical" else ''
    return f'<tr{row_style}><td class="check-num">{c["num"]}</td><td><div class="check-name">{c["name"]}</div><div class="check-group">{c["group"]}</div></td><td><span class="badge badge-{c["severity"]}">{SEV_LABELS[c["severity"]]}</span></td><td><span class="badge badge-{c["status"]}">{STATUS_LABELS[c["status"]]}</span></td><td>{ctrl_ids(c["soc2"])}</td><td>{ctrl_ids(c["nist"])}</td><td>{ctrl_ids(c["slsa"])}</td><td>{ctrl_ids(c["cato"])}</td><td>{ctrl_ids(c["pci"])}</td><td class="fix">{c["fix"]}</td></tr>'


def residual_card(r):
    return f'<div class="risk-card {r["severity"]}"><div class="risk-title">{r["title"]}</div><div class="risk-body">{r["body"]}</div></div>'


def residual_row(r):
    return f'<tr><td>{r["category"]}</td><td><strong style="color:{r["count_color"]}">{r["count"]}</strong></td><td><span class="badge badge-{r["severity"]}">{SEV_LABELS[r["severity"]]}</span></td><td>{ctrl_ids(r["soc2"])}</td><td>{ctrl_ids(r["nist"])}</td><td>{ctrl_ids(r["cato"])}</td><td>{ctrl_ids(r["pci"])}</td><td><span class="badge badge-{r["status_class"]}">{r["status_label"]}</span></td></tr>'


def nist_cell(c):
    return f'<div class="ctrl-cell {c["status"]}"><div class="ctrl-cell-id">{c["id"]}</div><div class="ctrl-cell-label">{c["label"]}</div></div>'


def policy_item(p):
    border = ' style="border-left:3px solid #ef4444"' if p.get("critical") else ''
    ctrl_html = "".join(f'<span class="ctrl-id">{c}</span>' for c in p["ctrls"])
    fw_html = "".join(f'<span class="fw-pill {cls}">{label}</span>' for cls, label in p["frameworks"])
    sev = "critical" if p.get("critical") else p["severity"]
    return f'<div class="policy-item"{border}><div class="policy-info"><div class="policy-name">{p["name"]}</div><div class="policy-desc">{p["desc"]}</div><div class="policy-meta"><span class="badge badge-{sev}">{SEV_LABELS[sev]}</span>{ctrl_html}{fw_html}</div></div><a href="{p["path"]}" target="_blank" style="font-size:11px;color:#38bdf8;text-decoration:underline">View policy \u2192</a></div>'


def remediation_block(r):
    diff_html = "".join(f'<span class="diff-{t}">{txt}</span>\n' for t, txt in r["diff_lines"])
    diff_label = f'<div class="diff-label">{r["diff_label"]}</div>' if r.get("diff_label") else ''
    return f'<div class="remediation"><div class="remediation-header"><div><div class="remediation-title">{r["id"]}: {r["title"]}</div><div style="font-size:11px;color:#64748b;margin-top:4px">Closes: {r["closes"]}</div></div><span class="approve-btn">\U0001f512 Approve to apply via MCP</span></div><div class="remediation-body">{diff_label}<pre class="diff-block">{diff_html}</pre></div></div>'


def evidence_item(e):
    return f'<div class="ev-item"><div class="ev-dot {e["dot"]}"></div><div class="ev-ts">{e["ts"]}</div><div class="ev-msg">{e["msg"]}</div></div>'


check_rows = "\n".join(check_row(c) for c in d["checks"])
residual_cards = "\n".join(residual_card(r) for r in d["residual_cards"])
residual_rows = "\n".join(residual_row(r) for r in d["residual_table"])
nist_cells = "\n".join(nist_cell(c) for c in d["nist_800_53"])
policies = "\n".join(policy_item(p) for p in d["policies"])
remediations = "\n".join(remediation_block(r) for r in d["remediations"])
evidence = "\n".join(evidence_item(e) for e in d["evidence_log"])

meta_items = "".join(f'<div class="meta-item"><div class="meta-label">{lbl}</div><div class="meta-value">{val}</div></div>' for lbl, val in [
    ("Account", d["account"]), ("Organization", d["org"]), ("Project", d["project"]),
    ("Pipeline", f'{d["pipeline_name"]} ({d["pipeline_id"]})'), ("Execution ID", d["execution_id"]),
    ("Run Sequence", f'#{d["run_sequence"]}'), ("Assessment Time", d["timestamp"]),
    ("Triggered By", d["triggered_by"]), ("Frameworks", d["frameworks_list"]),
    ("Branch / Commit", d["branch_commit"]), ("Repository", d["repository"]),
    ("Assessment Mode", d["assessment_mode"])
])

coverage_gap = d["coverage_total"] - d["coverage_covered"]
html = f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AGR Compliance Posture Assessment \u2014 {d["pipeline_name"]} | {d["project"]}</title>
<style>
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: #0f172a; color: #e2e8f0; font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.5; min-height: 100vh; }}
.page {{ max-width: 1400px; margin: 0 auto; padding: 32px 24px; }}
.header {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 60%, #0c1a2e 100%); border: 1px solid #334155; border-radius: 12px; padding: 36px 40px; margin-bottom: 28px; text-align: center; position: relative; overflow: hidden; }}
.header::before {{ content: ''; position: absolute; inset: 0; background: radial-gradient(ellipse at 50% 0%, rgba(56,189,248,0.07) 0%, transparent 70%); pointer-events: none; }}
.header-badge {{ display: inline-flex; align-items: center; gap: 8px; background: rgba(56,189,248,0.1); border: 1px solid rgba(56,189,248,0.3); border-radius: 100px; padding: 4px 16px; font-size: 11px; font-weight: 600; letter-spacing: 0.12em; text-transform: uppercase; color: #38bdf8; margin-bottom: 16px; }}
.header-badge::before {{ content: '\u25cf'; animation: pulse 2s infinite; }}
@keyframes pulse {{ 0%,100%{{opacity:1}} 50%{{opacity:0.4}} }}
h1.title {{ font-size: 2rem; font-weight: 800; letter-spacing: -0.02em; color: #f1f5f9; line-height: 1.2; margin-bottom: 8px; }}
h1.title span {{ color: #38bdf8; }}
.subtitle {{ font-size: 1rem; color: #94a3b8; margin-bottom: 24px; }}
.meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-top: 24px; }}
.meta-item {{ background: rgba(255,255,255,0.04); border: 1px solid #1e293b; border-radius: 8px; padding: 10px 14px; text-align: left; min-width: 0; overflow: hidden; }}
.meta-label {{ font-size: 10px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: #64748b; margin-bottom: 3px; }}
.meta-value {{ font-size: 13px; font-weight: 600; color: #cbd5e1; font-family: 'SF Mono', 'Fira Code', monospace; overflow-wrap: anywhere; word-break: break-word; }}
.summary-bar {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 28px; }}
.stat-card {{ background: #1e293b; border-radius: 10px; padding: 20px 24px; border: 1px solid #334155; position: relative; overflow: hidden; }}
.stat-card::after {{ content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 3px; }}
.stat-card.total::after {{ background: #38bdf8; }}
.stat-card.passed::after {{ background: #22c55e; }}
.stat-card.failed::after {{ background: #ef4444; }}
.stat-card.score::after {{ background: linear-gradient(90deg, #ef4444 0%, #f59e0b 50%, #22c55e 100%); }}
.stat-number {{ font-size: 2.4rem; font-weight: 800; line-height: 1; }}
.stat-number.blue {{ color: #38bdf8; }} .stat-number.green {{ color: #22c55e; }} .stat-number.red {{ color: #ef4444; }} .stat-number.amber {{ color: #f59e0b; }}
.stat-label {{ font-size: 11px; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; color: #64748b; margin-top: 4px; }}
.stat-sub {{ font-size: 11px; color: #475569; margin-top: 6px; }}
.section {{ margin-bottom: 28px; }}
.section-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 16px; }}
.section-header h2 {{ font-size: 0.95rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #94a3b8; }}
.section-header::before {{ content: ''; display: block; width: 3px; height: 18px; background: #38bdf8; border-radius: 2px; }}
.pass-1-badge {{ background: rgba(56,189,248,0.1); color: #38bdf8; border: 1px solid rgba(56,189,248,0.3); border-radius: 4px; padding: 2px 8px; font-size: 10px; font-weight: 700; letter-spacing: 0.1em; }}
.pass-2-badge {{ background: rgba(245,158,11,0.1); color: #f59e0b; border: 1px solid rgba(245,158,11,0.3); border-radius: 4px; padding: 2px 8px; font-size: 10px; font-weight: 700; letter-spacing: 0.1em; }}
.table-wrap {{ background: #1e293b; border-radius: 10px; border: 1px solid #334155; overflow: hidden; }}
table {{ width: 100%; border-collapse: collapse; }}
thead tr {{ background: #0f172a; border-bottom: 2px solid #334155; }}
thead th {{ padding: 11px 14px; text-align: left; font-size: 10px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: #475569; white-space: nowrap; }}
tbody tr {{ border-bottom: 1px solid #0f172a; transition: background 0.15s; }}
tbody tr:hover {{ background: rgba(56,189,248,0.04); }}
tbody td {{ padding: 11px 14px; font-size: 12.5px; vertical-align: top; }}
.check-num {{ font-weight: 700; color: #475569; font-size: 11px; }}
.check-name {{ font-weight: 600; color: #cbd5e1; }}
.check-group {{ font-size: 10px; color: #475569; margin-top: 2px; }}
.badge {{ display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 100px; font-size: 10px; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; white-space: nowrap; }}
.badge-critical {{ background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); }}
.badge-high {{ background: rgba(249,115,22,0.15); color: #f97316; border: 1px solid rgba(249,115,22,0.3); }}
.badge-medium {{ background: rgba(245,158,11,0.15); color: #f59e0b; border: 1px solid rgba(245,158,11,0.3); }}
.badge-low {{ background: rgba(148,163,184,0.15); color: #94a3b8; border: 1px solid rgba(148,163,184,0.3); }}
.badge-pass {{ background: rgba(34,197,94,0.12); color: #22c55e; border: 1px solid rgba(34,197,94,0.3); }}
.badge-fail {{ background: rgba(239,68,68,0.12); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); }}
.badge-na {{ background: rgba(148,163,184,0.1); color: #64748b; border: 1px solid rgba(148,163,184,0.2); }}
.badge-unable {{ background: rgba(245,158,11,0.1); color: #f59e0b; border: 1px solid rgba(245,158,11,0.2); }}
.ctrl-ids {{ display: flex; flex-wrap: wrap; gap: 3px; }}
.ctrl-id {{ background: rgba(56,189,248,0.08); color: #7dd3fc; border: 1px solid rgba(56,189,248,0.15); border-radius: 3px; padding: 1px 5px; font-size: 9.5px; font-weight: 600; font-family: 'SF Mono', 'Fira Code', monospace; white-space: nowrap; }}
.fix {{ font-size: 11.5px; color: #94a3b8; line-height: 1.45; }}
.fix strong {{ color: #cbd5e1; }}
.fix code {{ background: rgba(56,189,248,0.08); color: #7dd3fc; border-radius: 3px; padding: 0 4px; font-size: 10.5px; font-family: 'SF Mono', 'Fira Code', monospace; }}
.residual-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 28px; }}
.risk-card {{ background: #1e293b; border-radius: 10px; padding: 18px 20px; border: 1px solid #334155; }}
.risk-card.critical {{ border-left: 3px solid #ef4444; }}
.risk-card.high {{ border-left: 3px solid #f97316; }}
.risk-card.medium {{ border-left: 3px solid #f59e0b; }}
.risk-card.info {{ border-left: 3px solid #38bdf8; }}
.risk-title {{ font-weight: 700; color: #e2e8f0; margin-bottom: 8px; font-size: 13px; }}
.risk-body {{ font-size: 12px; color: #94a3b8; line-height: 1.5; }}
.risk-body strong {{ color: #cbd5e1; }}
.risk-body code {{ background: rgba(56,189,248,0.08); color: #7dd3fc; border-radius: 3px; padding: 0 4px; font-family: monospace; }}
.coverage-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(90px, 1fr)); gap: 8px; }}
.ctrl-cell {{ background: #1e293b; border-radius: 6px; padding: 8px 10px; border: 1px solid #334155; }}
.ctrl-cell.covered {{ border-color: rgba(34,197,94,0.3); background: rgba(34,197,94,0.05); }}
.ctrl-cell.gap {{ border-color: rgba(239,68,68,0.3); background: rgba(239,68,68,0.05); }}
.ctrl-cell-id {{ font-size: 10px; font-weight: 700; font-family: 'SF Mono', monospace; color: #94a3b8; }}
.ctrl-cell.covered .ctrl-cell-id {{ color: #22c55e; }}
.ctrl-cell.gap .ctrl-cell-id {{ color: #f87171; }}
.ctrl-cell-label {{ font-size: 9px; color: #475569; margin-top: 2px; }}
.remediation {{ background: #1e293b; border-radius: 10px; border: 1px solid #334155; margin-bottom: 14px; overflow: hidden; }}
.remediation-header {{ padding: 12px 18px; background: #0f172a; border-bottom: 1px solid #334155; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; }}
.remediation-title {{ font-weight: 700; color: #e2e8f0; font-size: 13px; }}
.remediation-body {{ padding: 18px; }}
.diff-block {{ background: #0f172a; border-radius: 6px; padding: 14px; font-family: 'SF Mono', monospace; font-size: 11px; line-height: 1.6; overflow-x: auto; margin: 8px 0; border: 1px solid #1e293b; white-space: pre; }}
.diff-add {{ color: #4ade80; }}
.diff-context {{ color: #64748b; }}
.diff-label {{ font-size: 10px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: #475569; margin-bottom: 6px; }}
.approve-btn {{ display: inline-flex; align-items: center; gap: 6px; background: rgba(56,189,248,0.1); color: #38bdf8; border: 1px solid rgba(56,189,248,0.3); border-radius: 6px; padding: 4px 12px; font-size: 11px; font-weight: 600; }}
.policy-list {{ display: flex; flex-direction: column; gap: 8px; }}
.policy-item {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 12px 16px; display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; flex-wrap: wrap; }}
.policy-info {{ flex: 1; min-width: 200px; }}
.policy-name {{ font-weight: 700; color: #7dd3fc; font-family: 'SF Mono', monospace; font-size: 12px; }}
.policy-desc {{ font-size: 11.5px; color: #94a3b8; margin-top: 3px; }}
.policy-meta {{ display: flex; gap: 6px; flex-wrap: wrap; margin-top: 6px; }}
.fw-pill {{ padding: 2px 8px; border-radius: 100px; font-size: 9.5px; font-weight: 700; }}
.fw-soc2 {{ background: rgba(167,139,250,0.15); color: #a78bfa; border: 1px solid rgba(167,139,250,0.3); }}
.fw-nist {{ background: rgba(56,189,248,0.12); color: #38bdf8; border: 1px solid rgba(56,189,248,0.25); }}
.fw-slsa {{ background: rgba(52,211,153,0.12); color: #34d399; border: 1px solid rgba(52,211,153,0.25); }}
.fw-cato {{ background: rgba(249,115,22,0.12); color: #fb923c; border: 1px solid rgba(249,115,22,0.25); }}
.fw-pci {{ background: rgba(244,63,94,0.12); color: #fb7185; border: 1px solid rgba(244,63,94,0.25); }}
.evidence-timeline {{ display: flex; flex-direction: column; gap: 0; }}
.ev-item {{ display: flex; gap: 14px; padding: 10px 0; border-bottom: 1px solid #1e293b; }}
.ev-dot {{ width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; margin-top: 5px; }}
.ev-dot.green {{ background: #22c55e; }} .ev-dot.red {{ background: #ef4444; }} .ev-dot.blue {{ background: #38bdf8; }} .ev-dot.amber {{ background: #f59e0b; }}
.ev-ts {{ font-family: 'SF Mono', monospace; font-size: 10px; color: #475569; flex-shrink: 0; width: 170px; }}
.ev-msg {{ font-size: 12px; color: #94a3b8; }}
.ev-msg strong {{ color: #cbd5e1; }}
.footer {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 14px 20px; text-align: center; margin-top: 32px; }}
.footer-text {{ font-size: 11px; color: #475569; letter-spacing: 0.04em; }}
.footer-text strong {{ color: #64748b; }}
@media (max-width: 768px) {{ .summary-bar {{ grid-template-columns: repeat(2, 1fr); }} .meta-grid {{ grid-template-columns: repeat(2, 1fr); }} h1.title {{ font-size: 1.4rem; }} }}
</style></head><body><div class="page">
<div class="header"><div class="header-badge">\U0001f512 ATO Evidence Package</div>
<h1 class="title">COMPLIANCE POSTURE <span>ASSESSMENT</span></h1>
<p class="subtitle">Automated Governance &amp; Remediation (AGR) \u2014 Two-Pass Compliance Analysis</p>
<div class="meta-grid">{meta_items}</div></div>
<div class="summary-bar">
<div class="stat-card total"><div class="stat-number blue">15</div><div class="stat-label">Total Checks</div><div class="stat-sub">Structural controls assessed</div></div>
<div class="stat-card passed"><div class="stat-number green">{d["passed"]}</div><div class="stat-label">Passed</div><div class="stat-sub">{d["passed_sub"]}</div></div>
<div class="stat-card failed"><div class="stat-number red">{d["failed"]}</div><div class="stat-label">Failed</div><div class="stat-sub">{d["failed_sub"]}</div></div>
<div class="stat-card score"><div class="stat-number amber">{d["score_pct"]}</div><div class="stat-label">Compliance Score</div><div class="stat-sub">Residual Risk: <strong style="color:#ef4444">{d["residual_risk_level"]}</strong></div></div>
</div>
<div class="section"><div class="section-header"><h2>Pass 1 \u2014 Structural Assessment</h2><span class="pass-1-badge">15-CONTROL CHECKLIST</span></div>
<div class="table-wrap"><table><thead><tr><th>#</th><th>Control</th><th>Severity</th><th>Status</th><th>SOC 2</th><th>NIST 800-53</th><th>SLSA</th><th>DoD cATO</th><th>PCI DSS 4.0</th><th>Finding &amp; Recommended Fix</th></tr></thead>
<tbody>{check_rows}</tbody></table></div></div>
<div class="section"><div class="section-header"><h2>Pass 2 \u2014 Residual Risk Assessment</h2><span class="pass-2-badge">EXECUTION ANALYSIS</span></div>
<div class="residual-grid">{residual_cards}</div>
<div class="table-wrap"><table><thead><tr><th>Residual Risk Category</th><th>Count</th><th>Severity</th><th>SOC 2</th><th>NIST 800-53</th><th>DoD cATO</th><th>PCI DSS 4.0</th><th>Status</th></tr></thead>
<tbody>{residual_rows}</tbody></table></div></div>
<div class="section"><div class="section-header"><h2>NIST SP 800-53 Control Coverage Grid</h2></div>
<div class="coverage-grid">{nist_cells}</div>
<div style="display:flex;gap:16px;margin-top:12px;font-size:11px;color:#64748b;">
<span style="display:flex;align-items:center;gap:6px;"><span style="width:10px;height:10px;background:rgba(34,197,94,0.3);border:1px solid #22c55e;border-radius:2px;display:inline-block"></span> Covered ({d["coverage_covered"]}/{d["coverage_total"]})</span>
<span style="display:flex;align-items:center;gap:6px;"><span style="width:10px;height:10px;background:rgba(239,68,68,0.2);border:1px solid #ef4444;border-radius:2px;display:inline-block"></span> Gap ({coverage_gap}/{d["coverage_total"]})</span>
</div></div>
<div class="section"><div class="section-header"><h2>Generated OPA Rego Policies</h2></div>
<div class="policy-list">{policies}</div></div>
<div class="section"><div class="section-header"><h2>Proposed Auto-Remediations</h2></div>
{remediations}</div>
<div class="section"><div class="section-header"><h2>AGR Evidence Log</h2></div>
<div class="table-wrap" style="padding:20px"><div class="evidence-timeline">{evidence}</div></div></div>
<div class="footer"><div class="footer-text">
<strong>Generated by AGR Agent</strong> &nbsp;|&nbsp; ATO Evidence Package &nbsp;|&nbsp; Do Not Modify &nbsp;|&nbsp;
Pipeline: {d["pipeline_name"]} ({d["pipeline_id"]}) &nbsp;|&nbsp; Execution: {d["execution_id"]} &nbsp;|&nbsp;
Run #{d["run_sequence"]} &nbsp;|&nbsp; {d["timestamp"]} &nbsp;|&nbsp; Account: {d["account"]} &nbsp;|&nbsp; Project: {d["project"]}
</div></div></div></body></html>'''

open('/harness/.agent/output/NIST_Control_Matrix.html', 'w').write(html)
print(f"Rendered {len(html)} bytes")
