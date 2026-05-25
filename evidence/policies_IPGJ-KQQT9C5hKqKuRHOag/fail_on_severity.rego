# METADATA
# title: Require fail_on_severity on All STO Scanner Steps
# description: >
#   Requires that every STO scanner step in the pipeline has fail_on_severity
#   set to "critical" or "high". Without this threshold, scanners run and
#   produce findings but never block the pipeline — critical CVEs and exposed
#   secrets ship silently. This policy covers all STO scanner step types.
# nist_controls:
#   - RA-5   (Vulnerability Monitoring and Scanning)
#   - SI-2   (Flaw Remediation)
# pipeline_stage: all stages with STO scanner steps
# gate: On Save — Error and Exit
# severity: high
# waiver_supported: true
# portability: Harness STO (pipeline_v1 / v0)

package fail_on_severity

import future.keywords.contains
import future.keywords.if
import future.keywords.in

sto_step_types := {
    "Gitleaks", "Semgrep", "Checkmarx", "SonarQube",
    "OsvScanner", "OWASPDepCheck", "Snyk", "Grype",
    "AquaTrivy", "Checkov", "Security", "SbomOrchestration"
}

acceptable_severities := {"critical", "high"}

deny contains msg if {
    stage := input.pipeline.stages[_].stage
    step  := stage.spec.execution.steps[_].step
    step.type in sto_step_types
    not valid_threshold(step)
    msg := sprintf(
        "STO step '%v' (type=%v) in stage '%v' is missing fail_on_severity set to 'critical' or 'high'. Without a threshold, findings are informational only and do not block the pipeline. Closes: SOC2 CC7.2/CC7.3 | NIST RA-5/SI-2 | cATO 3.2 | PCI 6.3.1/11.3.",
        [step.identifier, step.type, stage.identifier]
    )
}

valid_threshold(step) if {
    lower(step.spec.fail_on_severity) in acceptable_severities
}

valid_threshold(step) if {
    lower(step.spec.failOnSeverity) in acceptable_severities
}
