# AGR make_artifacts.py v1 — derive downstream JSON artifacts from agr-data.json
# Location in repo (REQUIRED): evidence/tooling/make_artifacts.py
# Run AFTER render.py (which materializes the merged, normalized agr-data.json).
# Reads env: MODE_DECISION, MODE_REASON, YAML_SHA256, BASELINE_TS, PIPE_KEY
# Writes:
#   - agr-assessment.json  (every mode)   downstream consumers: ServiceNow, JIRA, eMASS
#   - agr-baseline.json    (FULL mode)    delta cache for the next run
# The agent never writes these two files by hand and never modifies this script.

import datetime
import json
import os

BASE = '/harness/.agent/output'

d = json.load(open(f'{BASE}/agr-data.json'))
mode = os.environ.get('MODE_DECISION', 'FULL').strip().upper()
reason = os.environ.get('MODE_REASON', '')
yaml_sha = os.environ.get('YAML_SHA256', '')
baseline_ts = os.environ.get('BASELINE_TS', '')
pipe_key = os.environ.get('PIPE_KEY', '')
now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

assessment = {
    'execution': {
        'account': d['account'],
        'org': d['org'],
        'project': d['project'],
        'pipeline_id': d['pipeline_id'],
        'pipeline_name': d['pipeline_name'],
        'execution_id': d['execution_id'],
        'run_sequence': d['run_sequence'],
        'timestamp': d['timestamp'],
        'triggered_by': d['triggered_by'],
        'repository': d.get('repository', ''),
        'branch_commit': d.get('branch_commit', ''),
    },
    'mode': {
        'decision': mode,
        'reason': reason,
        'yaml_sha256': yaml_sha,
        'baseline_timestamp': baseline_ts,
    },
    'summary': {
        'passed': d['passed'],
        'failed': d['failed'],
        'unable': d['unable'],
        'na': d['na'],
        'score_pct': d['score_pct'],
        'residual_risk_level': d['residual_risk_level'],
        'frameworks': d.get('frameworks_list', ''),
    },
    'structural_findings': d['checks'],
    'residual_findings': {
        'cards': d['residual_cards'],
        'table': d['residual_table'],
    },
    'nist_800_53_coverage': {
        'grid': d['nist_800_53'],
        'covered': d['coverage_covered'],
        'total': d['coverage_total'],
    },
    'generated_policies': d['policies'],
    'proposed_remediations': d['remediations'],
    'evidence_log': d['evidence_log'],
}
json.dump(assessment, open(f'{BASE}/agr-assessment.json', 'w'), indent=2, ensure_ascii=False)
written = ['agr-assessment.json']

if mode != 'FULL':
    # Defense in depth: ensure no stale baseline from a previous container state
    # can be picked up by the push step (which also guards on MODE_DECISION).
    try:
        os.remove(f'{BASE}/agr-baseline.json')
    except FileNotFoundError:
        pass

if mode == 'FULL':
    baseline = {
        'pipeline_id': d['pipeline_id'],
        'org': d['org'],
        'project': d['project'],
        'pipe_key': pipe_key,
        'yaml_sha256': yaml_sha,
        'baseline_timestamp': now,
        'assessor_execution_id': d['execution_id'],
        'policy_dir': f"evidence/policies_{d['execution_id']}",
        'pass1': {
            'passed': d['passed'],
            'failed': d['failed'],
            'unable': d['unable'],
            'na': d['na'],
            'score_pct': d['score_pct'],
            'passed_sub': d['passed_sub'],
            'failed_sub': d['failed_sub'],
            'checks': d['checks'],
        },
        'policies': d['policies'],
        'remediations': d['remediations'],
        'nist_800_53': d['nist_800_53'],
        'coverage_covered': d['coverage_covered'],
        'coverage_total': d['coverage_total'],
    }
    json.dump(baseline, open(f'{BASE}/agr-baseline.json', 'w'), indent=2, ensure_ascii=False)
    written.append('agr-baseline.json')

print('make_artifacts wrote: ' + ', '.join(written) + f' (mode={mode})')
