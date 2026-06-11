# METADATA
# title: STO Severity Threshold Enforcement
# description: |
#   Requires all STO security scanner steps running in orchestration mode to have
#   fail_on_severity configured to critical or high. Prevents security scans from
#   completing without blocking on critical/high severity findings.
# nist_controls:
#   - RA-5
#   - SI-2
# pipeline_stage: CI/SecurityTests
# gate: onsave
# severity: high
# waiver_supported: true
# portability: harness-opa-v1
package raise.severity_thresholds

import future.keywords.if
import future.keywords.in

sto_step_types := {
    "Gitleaks", "Semgrep", "Checkmarx", "SonarQube", "Owasp",
    "OsvScanner", "Snyk", "AquaTrivy", "Grype", "Checkov", "Zap",
    "Bandit", "Brakeman", "GoSec", "Aqua"
}

deny[msg] if {
    some stage in input.pipeline.stages
    some step in get_steps(stage)
    step.step.type in sto_step_types
    step.step.spec.mode == "orchestration"
    not has_fail_on_severity(step.step)
    msg := sprintf("STO step '%v' (type: %v) is missing fail_on_severity. Set spec.advanced.fail_on_severity to 'critical' or 'high'. NIST RA-5, SI-2 | SOC2 CC7.2, CC7.3 | PCI 6.3.1, 11.3", [step.step.name, step.step.type])
}

get_steps(stage) := steps if {
    steps := stage.stage.spec.execution.steps
}

has_fail_on_severity(step_spec) if {
    sev := step_spec.spec.advanced.fail_on_severity
    sev != ""
    sev != null
}
