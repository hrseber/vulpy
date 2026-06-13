# METADATA
# title: STO Scanner Severity Threshold Enforcement
# description: |
#   All STO (Security Testing Orchestration) scanner steps in a pipeline MUST have
#   fail_on_severity set to "critical" or "high". Additionally, no STO scanner step
#   should have a blanket MarkAsSuccess or Ignore failure strategy that would bypass
#   the severity gate. This prevents Critical and High CVEs from shipping without
#   explicit human review and approval.
# nist_controls:
#   - RA-5: Vulnerability Scanning
#   - SI-2: Flaw Remediation
# pipeline_stage: CI (security scan steps)
# gate: On Run, On Save
# severity: CRITICAL
# waiver_supported: true
# portability: Harness Policy Engine (OPA)
package harness.pipeline.sto_severity_threshold

import future.keywords.if
import future.keywords.in

sto_types := {
  "Gitleaks", "HarnessSAST", "HarnessSCA", "Semgrep", "Checkmarx",
  "SonarQube", "Sonarqube", "Snyk", "BlackDuck", "AquaTrivy",
  "Grype", "Wiz", "Traceable", "Security"
}

blocking_severities := {"critical", "high", "Critical", "High"}
bypass_strategies := {"MarkAsSuccess", "Ignore"}

# Collect all STO steps from the pipeline
sto_steps[step] {
  stage := input.pipeline.stages[_].stage
  step := stage.spec.execution.steps[_].step
  step.type in sto_types
}

sto_steps[step] {
  stage := input.pipeline.stages[_].stage
  group := stage.spec.execution.steps[_].stepGroup
  step := group.steps[_].parallel[_].step
  step.type in sto_types
}

# Deny if any STO step lacks fail_on_severity or has it set to "none"
deny[msg] {
  step := sto_steps[_]
  not step_has_blocking_threshold(step)
  msg := sprintf("FAIL RA-5/SI-2: STO step '%v' (type: %v) does not have fail_on_severity set to 'critical' or 'high'. Critical and High vulnerabilities will not block the pipeline.", [step.identifier, step.type])
}

# Deny if any STO step has a bypass failure strategy
deny[msg] {
  step := sto_steps[_]
  strategy := step.failureStrategies[_].onFailure.action.type
  strategy in bypass_strategies
  msg := sprintf("FAIL RA-5/SI-2: STO step '%v' has failure strategy '%v' which bypasses severity threshold enforcement. Remove or replace with conditional waiver logic.", [step.identifier, strategy])
}

step_has_blocking_threshold(step) if {
  threshold := step.spec.advanced.fail_on_severity
  lower(threshold) in {"critical", "high"}
}
