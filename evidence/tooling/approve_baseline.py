# Drift Sentinel — approve_baseline.py v1
# Location in repo (REQUIRED): evidence/tooling/approve_baseline.py
# Purpose: capture the CURRENT pipeline configuration as the AUTHORIZED BASELINE for a pipeline.
# This is the human-gated re-baseline action. It is run by a SEPARATE approve-baseline pipeline
# (which should sit behind a HarnessApproval step), NEVER by the Drift Sentinel itself.
#
# Inputs:
#   /tmp/target-pipeline.yaml   pipeline YAML, byte-exact from MCP (required)
#   env: PIPE_KEY (required)
#   env authorization metadata (all optional but strongly recommended for Federal):
#       ATO_ID, ATO_DATE, CONTROL_SET, APPROVED_BY, CHANGE_TICKET
# Output:
#   /harness/.agent/output/authorized-baseline-new.json   to push to evidence/drift/authorized-baseline-<PIPE_KEY>.json
#   /harness/.agent/output/authorized-baseline-append.jsonl  audit line for the authorization log
#
# The authorized baseline is identical in SHAPE to a rolling state snapshot (so drift_analyzer.py
# can diff against it with the same code path) PLUS an 'authorization' block recording who approved
# it, when, and under what ATO. The Sentinel never writes this file; only this action does.

import datetime
import importlib.util
import json
import os
import sys

BASE = '/harness/.agent/output'

# Reuse build_snapshot from the analyzer so the baseline shape can never drift from the comparator.
analyzer_path = f'{BASE}/drift_analyzer.py'
if not os.path.exists(analyzer_path):
    print("FATAL: drift_analyzer.py not found alongside approve_baseline.py; fetch it first")
    sys.exit(1)
spec = importlib.util.spec_from_file_location('drift_analyzer', analyzer_path)
da = importlib.util.module_from_spec(spec)
spec.loader.exec_module(da)

pipeline_bytes = open('/tmp/target-pipeline.yaml', 'rb').read()
snap = da.build_snapshot(pipeline_bytes)

now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
authorization = {k: v for k, v in {
    'ato_id': os.environ.get('ATO_ID', '').strip(),
    'ato_date': os.environ.get('ATO_DATE', '').strip(),
    'control_set': os.environ.get('CONTROL_SET', '').strip(),
    'approved_by': os.environ.get('APPROVED_BY', '').strip(),
    'change_ticket': os.environ.get('CHANGE_TICKET', '').strip(),
    'approved_at': now,
}.items() if v}

snap['authorization'] = authorization
json.dump(snap, open(f'{BASE}/authorized-baseline-new.json', 'w'), indent=2, ensure_ascii=False)

with open(f'{BASE}/authorized-baseline-append.jsonl', 'w') as h:
    h.write(json.dumps({
        'event': 'BASELINE_AUTHORIZED',
        'ts': now,
        'pipe_key': snap['pipe_key'],
        'pipeline_id': snap['pipeline_id'],
        'yaml_sha256': snap['yaml_sha256'],
        'monitored_stages': len(snap['stages']),
        'monitored_steps': len(snap['steps']),
        'authorization': authorization,
    }) + '\n')

print(f"BASELINE_AUTHORIZED pipe={snap['pipe_key']}")
print(f"YAML_SHA256={snap['yaml_sha256']}")
print(f"AUTHORIZATION={json.dumps(authorization)}")
print(f"MONITORED steps={len(snap['steps'])} stages={len(snap['stages'])} templates={len(snap['templates'])}")
missing = [k for k in ('ato_id', 'ato_date', 'approved_by') if k not in authorization]
if missing:
    print(f"WARNING: authorization metadata incomplete (missing: {', '.join(missing)}). "
          f"For Federal use, an authorized baseline should record at least ATO_ID, ATO_DATE, and APPROVED_BY.")
