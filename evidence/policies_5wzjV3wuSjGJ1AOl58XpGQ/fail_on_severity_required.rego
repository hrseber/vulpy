# METADATA
# title: STO Scanners Must Set fail_on_severity
# description: Every STO scanner step (Semgrep, Gitleaks, AquaTrivy, Owasp, OsvScanner, Zap)
#              must have fail_on_severity set to critical or high. Steps that use failureStrategies
#              type=Ignore without a threshold effectively run in advisory-only mode, allowing
#              critical vulnerabilities to ship silently.
# nist_controls: ["RA-5", "SI-2"]
# pipeline_stage: CI
# gate: onsave
# severity: high
# waiver_supported: true
# portability: harness-opa-v1

package pipeline_raise_fail_on_severity

import future.keywords.in

sto_types := {"Semgrep", "Gitleaks", "AquaTrivy", "Owasp", "OsvScanner", "Zap", "Checkmarx", "Snyk", "Grype"}

deny[msg] {
  step := input.pipeline.stages[_].stage.spec.execution.steps[_].step
  step.type in sto_types
  not step.spec.advanced.fail_on_severity
  msg := sprintf("RAISE Check 11: STO step '%v' (type: %v) does not have fail_on_severity configured. Set fail_on_severity to 'critical' or 'high' to enforce zero-tolerance vulnerability policy.", [step.name, step.type])
}
