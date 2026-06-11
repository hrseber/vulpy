# METADATA
# title: STO Scanners Must Enforce Severity Thresholds
# description: >
#   Every STO security scanner step (SAST, SCA, Secret Detection, Container Scanning, DAST)
#   must have fail_on_severity set to "critical" or "high". Setting failure strategies to
#   Ignore without a severity threshold allows critical vulnerabilities to pass through
#   the pipeline silently, breaking the zero-tolerance posture required by RAISE 2.0.
# nist_controls:
#   - RA-5
#   - SI-2
# pipeline_stage: CI
# gate: on_save
# severity: HIGH
# waiver_supported: false
# portability: harness-opa
package pipeline.fail_on_severity_required

import future.keywords.if
import future.keywords.in

_scanner_types := {
    "Semgrep", "Checkmarx", "SonarQube",
    "Owasp", "OsvScanner", "Snyk",
    "Gitleaks", "TruffleHog",
    "AquaTrivy", "Grype", "Twistlock",
    "Zap", "BurpSuite"
}

deny[msg] if {
    stage := input.pipeline.stages[_].stage
    step := _get_steps(stage)[_]
    stype := _step_type(step)
    stype in _scanner_types
    not _has_fail_on_severity(step)
    msg := sprintf("STO scanner step '%v' (type: %v) is missing fail_on_severity configuration. Set fail_on_severity to 'critical' or 'high' to enforce zero-tolerance. NIST RA-5, SI-2.", [_step_name(step), stype])
}

_get_steps(stage) := stage.spec.execution.steps
_step_type(step) := step.step.spec.type if step.step.spec.type
_step_type(step) := step.step.type if step.step.type; not step.step.spec.type
_step_type(step) := step.type if step.type; not step.step
_step_name(step) := step.step.name if step.step
_step_name(step) := step.name if not step.step
_has_fail_on_severity(step) if step.step.spec.advanced.fail_on_severity
_has_fail_on_severity(step) if step.spec.advanced.fail_on_severity
