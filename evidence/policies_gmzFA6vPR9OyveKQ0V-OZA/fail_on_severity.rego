# METADATA
# title: STO Severity Threshold Enforcement
# description: All STO scanner steps must have fail_on_severity set to critical or high. Pipelines using custom Run scripts for scanning must be migrated to native STO steps to enable threshold enforcement. Accepting HIGH findings without blocking violates baseline vulnerability management posture.
# nist_controls: [RA-5, SI-2]
# pipeline_stage: ci_static_analysis, ci_dynamic_analysis
# gate: on-run
# severity: high
# waiver_supported: true
# portability: harness-opa

package fail_on_severity

import future.keywords.in

sto_step_types := {"Semgrep","Checkmarx","SonarQube","OWASP","Snyk","Gitleaks","AquaTrivy","Grype","Checkov","ZAP","Burp","HCLAppScan","Bandit"}
acceptable_thresholds := {"critical","high"}

deny[msg] {
    some stage in input.pipeline.stages
    some step in stage.stage.spec.execution.steps
    step.step.type in sto_step_types
    not step.step.spec.advanced.fail_on_severity
    msg := sprintf("STO step '%v' (type: %v) is missing fail_on_severity. All scanners must block on critical or high findings. SOC2 CC7.2/CC7.3, NIST RA-5/SI-2, PCI 6.3.1/11.3.", [step.step.name, step.step.type])
}

deny[msg] {
    some stage in input.pipeline.stages
    some step in stage.stage.spec.execution.steps
    step.step.type in sto_step_types
    threshold := step.step.spec.advanced.fail_on_severity
    not threshold in acceptable_thresholds
    msg := sprintf("STO step '%v' has fail_on_severity='%v' which is below the required threshold. Must be 'critical' or 'high'.", [step.step.name, threshold])
}
