# Drift Sentinel — drift_analyzer.py v1
# Location in repo (REQUIRED): evidence/tooling/drift_analyzer.py
# Inputs:
#   /tmp/target-pipeline.yaml   pipeline YAML, byte-exact from MCP (required)
#   /tmp/drift-state.json       prior state from evidence/drift/ (optional; absent = BASELINE run)
#   /tmp/templates/*.yaml       optional fetched template bodies named <ref>__<version>.yaml (content mode)
#   env: PIPE_KEY, EXECUTION_ID, RUN_SEQUENCE
# Outputs:
#   /harness/.agent/output/drift-report.json        findings + verdict for the renderer
#   /harness/.agent/output/drift-state-new.json     state to push back to the repo
#   /harness/.agent/output/drift-history-append.jsonl  lines to append to the repo history
#   appends VERDICT / MAX_SEVERITY / YAML_SHA256 exports to /tmp/drift-env.sh
# The agent never modifies this file. All severity logic is mechanical and lives here.

import datetime
import glob
import hashlib
import json
import os
import sys

try:
    import yaml
except ImportError:
    print("FATAL: pyyaml not available in this container")
    sys.exit(1)

BASE = '/harness/.agent/output'
SCHEMA_VERSION = 1

SEC_TYPES = {
    'Gitleaks', 'Semgrep', 'Owasp', 'OsvScanner', 'Snyk', 'BlackDuck', 'AquaTrivy',
    'Wiz', 'HarnessSAST', 'HarnessSCA', 'Sonarqube', 'Checkmarx', 'Security',
    'Traceable', 'Zap', 'Checkov', 'Grype',
    'SscaOrchestration', 'SscaArtifactSigning', 'SscaArtifactVerification', 'provenance',
}
GATE_TYPES = {
    'HarnessApproval', 'JiraApproval', 'ServiceNowApproval', 'IACMApproval',
    'Policy', 'Verify', 'AiVerify',
}
WEAK_ACTIONS = {'Ignore', 'MarkAsSuccess'}
SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'info': 1}
FOS_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'none': 0}


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def find_key(node, key):
    if isinstance(node, dict):
        if key in node:
            return node[key]
        for v in node.values():
            r = find_key(v, key)
            if r is not None:
                return r
    elif isinstance(node, list):
        for v in node:
            r = find_key(v, key)
            if r is not None:
                return r
    return None


def failure_actions(node):
    out = []
    for fs in node.get('failureStrategies') or []:
        try:
            out.append(fs['onFailure']['action']['type'])
        except (KeyError, TypeError):
            pass
    return sorted(out)


def when_of(node):
    w = node.get('when') or {}
    if not isinstance(w, dict):
        return {'condition': None, 'status': None}
    return {'condition': str(w.get('condition')) if w.get('condition') is not None else None,
            'status': w.get('stageStatus') or w.get('pipelineStatus')}


def step_record(step, stage_id):
    spec = step.get('spec') or {}
    tpl = step.get('template') or None
    flags = {}
    fos = find_key(spec, 'fail_on_severity')
    if fos is not None:
        flags['fail_on_severity'] = str(fos).lower()
    auto = find_key(spec, 'autoApprove')
    if auto is not None:
        flags['autoApprove'] = bool(auto)
    minc = find_key(spec, 'minimumCount')
    if minc is not None:
        flags['minimumCount'] = int(minc)
    psets = spec.get('policySets')
    if isinstance(psets, list):
        flags['policySets'] = sorted(str(p) for p in psets)
    rec = {
        'type': step.get('type') or ('template' if tpl else 'unknown'),
        'name': step.get('name', ''),
        'when': when_of(step),
        'failure_actions': failure_actions(step),
        'flags': flags,
        'stage': stage_id,
    }
    if tpl:
        rec['template'] = {'ref': str(tpl.get('templateRef', '')),
                          'version': str(tpl.get('versionLabel', ''))}
    return rec


def walk_steps(items, stage_id, prefix, out, templates):
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, dict):
            continue
        if 'step' in item:
            s = item['step']
            ident = s.get('identifier', s.get('name', '?'))
            rec = step_record(s, stage_id)
            out[f"{prefix}{ident}"] = rec
            if 'template' in rec:
                templates[rec['template']['ref']] = rec['template']['version']
        elif 'stepGroup' in item:
            g = item['stepGroup']
            gid = g.get('identifier', g.get('name', 'group'))
            walk_steps(g.get('steps'), stage_id, f"{prefix}{gid}/", out, templates)
        elif 'parallel' in item:
            walk_steps(item['parallel'], stage_id, prefix, out, templates)


def build_snapshot(pipeline_bytes):
    doc = yaml.safe_load(pipeline_bytes)
    pl = doc.get('pipeline', doc)
    stages, steps, templates = {}, {}, {}

    def walk_stage(st):
        sid = st.get('identifier', st.get('name', '?'))
        rec = {'type': st.get('type', ''), 'name': st.get('name', ''), 'when': when_of(st)}
        tpl = st.get('template')
        if tpl:
            rec['template'] = {'ref': str(tpl.get('templateRef', '')),
                               'version': str(tpl.get('versionLabel', ''))}
            templates[rec['template']['ref']] = rec['template']['version']
            rec['type'] = rec['type'] or 'TemplatedStage'
        stages[sid] = rec
        spec = st.get('spec') or {}
        exe = spec.get('execution') or {}
        walk_steps(exe.get('steps'), sid, f"{sid}/", steps, templates)
        walk_steps(exe.get('rollbackSteps'), sid, f"{sid}/rollback/", steps, templates)

    for entry in pl.get('stages') or []:
        if 'stage' in entry:
            walk_stage(entry['stage'])
        elif 'parallel' in entry:
            for sub in entry['parallel']:
                if 'stage' in sub:
                    walk_stage(sub['stage'])

    template_hashes = {}
    for path in glob.glob('/tmp/templates/*.yaml'):
        name = os.path.basename(path)[:-5]
        template_hashes[name] = sha256_bytes(open(path, 'rb').read())

    return {
        'schema_version': SCHEMA_VERSION,
        'yaml_sha256': sha256_bytes(pipeline_bytes),
        'captured_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'execution_id': os.environ.get('EXECUTION_ID', ''),
        'run_sequence': os.environ.get('RUN_SEQUENCE', ''),
        'pipe_key': os.environ.get('PIPE_KEY', ''),
        'pipeline_name': pl.get('name', ''),
        'pipeline_id': pl.get('identifier', ''),
        'stages': stages,
        'steps': steps,
        'templates': templates,
        'template_hashes': template_hashes,
    }


def is_protective(t):
    return t in SEC_TYPES or t in GATE_TYPES


def diff(prior, snap):
    findings = []

    def add(sev, cat, loc, before, after, detail):
        findings.append({'id': f'DR-{len(findings) + 1:02d}', 'severity': sev, 'category': cat,
                         'location': loc, 'before': before, 'after': after, 'detail': detail})

    op, np_ = prior['stages'], snap['stages']
    for sid in sorted(set(op) - set(np_)):
        t = op[sid].get('type', '')
        sev = 'critical' if t in ('Approval', 'Deployment') else 'medium'
        add(sev, 'STAGE_REMOVED', sid, f"{t} stage present", 'absent',
            f"Stage '{op[sid].get('name', sid)}' was removed from the pipeline.")
    for sid in sorted(set(np_) - set(op)):
        add('info', 'STAGE_ADDED', sid, 'absent', f"{np_[sid].get('type', '')} stage present",
            f"New stage '{np_[sid].get('name', sid)}' added.")
    for sid in sorted(set(op) & set(np_)):
        o, n = op[sid], np_[sid]
        if o['when'] != n['when']:
            sev = 'high' if n['when'].get('condition') == 'false' and o['when'].get('condition') != 'false' else 'medium'
            add(sev, 'STAGE_CONDITION_CHANGED', sid, json.dumps(o['when']), json.dumps(n['when']),
                f"Execution condition of stage '{sid}' changed.")
        ot, nt = o.get('template'), n.get('template')
        if ot and nt and ot != nt:
            add('medium', 'TEMPLATE_VERSION_CHANGED', sid,
                f"{ot['ref']} v{ot['version']}", f"{nt['ref']} v{nt['version']}",
                "Stage template reference changed; review the template delta.")

    os_, ns = prior['steps'], snap['steps']
    for p in sorted(set(os_) - set(ns)):
        t = os_[p]['type']
        sev = 'critical' if is_protective(t) else 'medium'
        add(sev, 'STEP_REMOVED', p, f"{t} step present", 'absent',
            ("Protective control removed from the pipeline." if is_protective(t)
             else "Step removed from the pipeline."))
    for p in sorted(set(ns) - set(os_)):
        t = ns[p]['type']
        add('info', 'STEP_ADDED', p, 'absent', f"{t} step present",
            ("Protective control added (positive change)." if is_protective(t) else "Step added."))

    for p in sorted(set(os_) & set(ns)):
        o, n = os_[p], ns[p]
        t = n['type']
        prot = is_protective(t) or is_protective(o['type'])
        if o['type'] != n['type']:
            add('medium', 'STEP_TYPE_CHANGED', p, o['type'], n['type'], 'Step type changed in place.')
        if o['when'] != n['when']:
            oc, nc = o['when'].get('condition'), n['when'].get('condition')
            if nc == 'false' and oc != 'false' and prot:
                add('critical', 'GATE_DISABLED', p, json.dumps(o['when']), json.dumps(n['when']),
                    'Protective step condition set to "false" — this control can no longer execute.')
            elif oc == 'false' and nc != 'false' and prot:
                add('info', 'GATE_REENABLED', p, json.dumps(o['when']), json.dumps(n['when']),
                    'Previously disabled protective step re-enabled (positive change).')
            else:
                add('medium', 'CONDITION_CHANGED', p, json.dumps(o['when']), json.dumps(n['when']),
                    'Execution condition changed.')
        if o['failure_actions'] != n['failure_actions']:
            o_weak = any(a in WEAK_ACTIONS for a in o['failure_actions'])
            n_weak = any(a in WEAK_ACTIONS for a in n['failure_actions'])
            if n_weak and not o_weak and prot:
                add('high', 'FAILURE_STRATEGY_WEAKENED', p,
                    str(o['failure_actions'] or ['<default: blocking>']), str(n['failure_actions']),
                    'Protective step failures are now swallowed — the gate cannot block.')
            elif o_weak and not n_weak and prot:
                add('info', 'FAILURE_STRATEGY_STRENGTHENED', p,
                    str(o['failure_actions']), str(n['failure_actions'] or ['<default: blocking>']),
                    'Failure handling strengthened (positive change).')
            else:
                add('info', 'FAILURE_STRATEGY_CHANGED', p,
                    str(o['failure_actions']), str(n['failure_actions']), 'Failure strategy changed.')
        of, nf = o['flags'], n['flags']
        if of.get('fail_on_severity') != nf.get('fail_on_severity'):
            ov = FOS_RANK.get(str(of.get('fail_on_severity')), -1)
            nv = FOS_RANK.get(str(nf.get('fail_on_severity')), -1)
            if of.get('fail_on_severity') is not None and nv < ov:
                add('high', 'THRESHOLD_WEAKENED', p,
                    f"fail_on_severity={of.get('fail_on_severity')}",
                    f"fail_on_severity={nf.get('fail_on_severity')}",
                    'Scanner blocking threshold lowered.')
            else:
                add('info', 'THRESHOLD_CHANGED', p,
                    f"fail_on_severity={of.get('fail_on_severity')}",
                    f"fail_on_severity={nf.get('fail_on_severity')}",
                    'Scanner threshold changed (raised or newly set).')
        if of.get('autoApprove') != nf.get('autoApprove'):
            if nf.get('autoApprove') is True:
                add('critical', 'APPROVAL_AUTO_APPROVED', p,
                    f"autoApprove={of.get('autoApprove')}", 'autoApprove=true',
                    'Approval step now auto-approves — human review removed.')
            else:
                add('info', 'APPROVAL_MANUAL_RESTORED', p,
                    f"autoApprove={of.get('autoApprove')}", f"autoApprove={nf.get('autoApprove')}",
                    'Auto-approval removed (positive change).')
        if of.get('minimumCount') is not None and nf.get('minimumCount') is not None \
                and nf['minimumCount'] < of['minimumCount']:
            add('high', 'APPROVERS_REDUCED', p,
                f"minimumCount={of['minimumCount']}", f"minimumCount={nf['minimumCount']}",
                'Required approver count lowered.')
        if of.get('policySets') != nf.get('policySets'):
            removed = sorted(set(of.get('policySets') or []) - set(nf.get('policySets') or []))
            sev = 'high' if removed else 'medium'
            add(sev, 'POLICY_SETS_CHANGED', p,
                str(of.get('policySets')), str(nf.get('policySets')),
                (f"Policy set(s) removed from enforcement: {removed}" if removed
                 else 'Policy set list changed.'))
        ot, nt = o.get('template'), n.get('template')
        if ot and nt and ot != nt:
            add('medium', 'TEMPLATE_VERSION_CHANGED', p,
                f"{ot['ref']} v{ot['version']}", f"{nt['ref']} v{nt['version']}",
                'Step template reference changed; review the template delta.')

    oth, nth = prior.get('template_hashes', {}), snap.get('template_hashes', {})
    for name in sorted(set(oth) & set(nth)):
        if oth[name] != nth[name]:
            add('high', 'TEMPLATE_CONTENT_CHANGED', name,
                f"sha {oth[name][:12]}", f"sha {nth[name][:12]}",
                'Template content changed under the SAME version label — silent template drift.')
    return findings


def main():
    pipeline_bytes = open('/tmp/target-pipeline.yaml', 'rb').read()
    snap = build_snapshot(pipeline_bytes)
    prior = None
    if os.path.exists('/tmp/drift-state.json'):
        try:
            prior = json.load(open('/tmp/drift-state.json'))
            if prior.get('schema_version') != SCHEMA_VERSION:
                print(f"NOTE: prior state schema v{prior.get('schema_version')} != v{SCHEMA_VERSION}; re-baselining")
                prior = None
        except Exception as e:
            print(f"NOTE: prior state unreadable ({e}); re-baselining")
            prior = None

    if prior is None:
        verdict, findings = 'BASELINE', []
    elif prior['yaml_sha256'] == snap['yaml_sha256'] and \
            prior.get('template_hashes', {}) == snap.get('template_hashes', {}):
        verdict, findings = 'NO_DRIFT', []
    else:
        findings = diff(prior, snap)
        findings.sort(key=lambda f: -SEV_RANK.get(f['severity'], 0))
        for i, f in enumerate(findings, 1):
            f['id'] = f'DR-{i:02d}'
        verdict = 'DRIFT' if findings else 'NO_DRIFT'

    counts = {s: sum(1 for f in findings if f['severity'] == s) for s in SEV_RANK}
    max_sev = next((s for s in ('critical', 'high', 'medium', 'info') if counts.get(s)), 'none')
    report = {
        'verdict': verdict,
        'max_severity': max_sev,
        'counts': counts,
        'pipe_key': snap['pipe_key'],
        'pipeline_name': snap['pipeline_name'],
        'pipeline_id': snap['pipeline_id'],
        'execution_id': snap['execution_id'],
        'run_sequence': snap['run_sequence'],
        'captured_at': snap['captured_at'],
        'yaml_sha256': snap['yaml_sha256'],
        'prior_captured_at': prior['captured_at'] if prior else None,
        'prior_run_sequence': prior.get('run_sequence') if prior else None,
        'prior_yaml_sha256': prior['yaml_sha256'] if prior else None,
        'monitored_steps': len(snap['steps']),
        'monitored_stages': len(snap['stages']),
        'templates': snap['templates'],
        'prior_templates': prior.get('templates', {}) if prior else {},
        'findings': findings,
    }
    json.dump(report, open(f'{BASE}/drift-report.json', 'w'), indent=2, ensure_ascii=False)
    json.dump(snap, open(f'{BASE}/drift-state-new.json', 'w'), indent=2, ensure_ascii=False)

    with open(f'{BASE}/drift-history-append.jsonl', 'w') as h:
        h.write(json.dumps({'ts': snap['captured_at'], 'run': snap['run_sequence'],
                            'execution': snap['execution_id'], 'verdict': verdict,
                            'max_severity': max_sev, 'counts': counts,
                            'yaml_sha256': snap['yaml_sha256']}) + '\n')
        for f in findings:
            h.write(json.dumps({'ts': snap['captured_at'], 'run': snap['run_sequence'], **f}) + '\n')

    with open('/tmp/drift-env.sh', 'a') as f:
        f.write(f'export VERDICT="{verdict}"\n')
        f.write(f'export MAX_SEVERITY="{max_sev}"\n')
        f.write(f'export YAML_SHA256="{snap["yaml_sha256"]}"\n')

    print(f"VERDICT={verdict}")
    print(f"MAX_SEVERITY={max_sev}")
    print(f"COUNTS={json.dumps(counts)}")
    print(f"MONITORED steps={len(snap['steps'])} stages={len(snap['stages'])} templates={len(snap['templates'])}")
    print(f"YAML_SHA256={snap['yaml_sha256']}")
    print(f"TEMPLATES_REFERENCED={json.dumps(snap['templates'])}")
    for f in findings:
        print(f"{f['id']} [{f['severity'].upper()}] {f['category']} @ {f['location']}")


if __name__ == '__main__':
    main()
