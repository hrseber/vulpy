# METADATA
# title: Require Secret Detection Scanner (Gitleaks / Trufflehog)
# description: >
#   Requires that a secret-detection scanner (Gitleaks, Trufflehog, or equivalent
#   STO secret-scan step) runs before any artifact is built or pushed.
#   Secret leaks in source code are the single highest-impact, lowest-cost-to-fix
#   finding class. Shipping a credential embedded in an image is irreversible
#   without a full secret rotation event. CRITICAL severity.
# nist_controls:
#   - IA-5   (Authenticator Management)
#   - SC-28  (Protection of Information at Rest)
# pipeline_stage: ci_static_analysis (before ci_package)
# gate: On Run — Error and Exit
# severity: critical
# waiver_supported: false
# portability: Harness STO (pipeline_v1 / v0)

package secret_detection

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny contains msg if {
    not secret_scanner_present
    msg := sprintf(
        "CRITICAL: Pipeline '%v' has no secret-detection scanner (Gitleaks, Trufflehog, or STO type=Secret). A committed secret shipped in an image cannot be recalled. Add a Gitleaks step as the FIRST step in the CI_Static_Analysis stage. Closes: SOC2 CC6.1/CC6.7 | NIST IA-5/SC-28 | cATO 1.0 | PCI 8.2/8.6.",
        [input.pipeline.identifier]
    )
}

secret_scanner_present if {
    stage := input.pipeline.stages[_].stage
    step  := stage.spec.execution.steps[_].step
    step.type == "Gitleaks"
}

secret_scanner_present if {
    stage := input.pipeline.stages[_].stage
    step  := stage.spec.execution.steps[_].step
    step.type == "Security"
    lower(step.spec.type) == "gitleaks"
}

secret_scanner_present if {
    stage := input.pipeline.stages[_].stage
    step  := stage.spec.execution.steps[_].step
    step.type == "Security"
    lower(step.spec.type) == "trufflehog"
}
