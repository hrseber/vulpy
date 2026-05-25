# METADATA
# title: Require SBOM Policy Enforcement Step
# description: >
#   Enforces that every pipeline with SBOM generation also includes an
#   SbomPolicyEnforcement step with deny/allow lists configured.
#   SBOM generation without policy enforcement provides no actual supply-chain
#   gate — components appear in the BOM but nothing blocks prohibited packages.
# nist_controls:
#   - SR-3   (Supply Chain Controls and Processes)
#   - SR-11  (Component Authenticity)
# pipeline_stage: after SbomOrchestration
# gate: On Run — Error and Exit
# severity: high
# waiver_supported: true
# portability: Harness SCS (pipeline_v1 / v0)

package sbom_policy_enforcement

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny contains msg if {
    # SBOM is generated...
    sbom_step_exists
    # ...but no enforcement step present
    not enforcement_step_exists
    msg := sprintf(
        "Pipeline '%v' generates an SBOM but has no SbomPolicyEnforcement step. Add an SbomPolicyEnforcement step with deny/allow lists to satisfy SR-3, SR-11, and SLSA L2.",
        [input.pipeline.identifier]
    )
}

sbom_step_exists if {
    stage := input.pipeline.stages[_].stage
    step  := stage.spec.execution.steps[_].step
    step.type == "SbomOrchestration"
}

enforcement_step_exists if {
    stage := input.pipeline.stages[_].stage
    step  := stage.spec.execution.steps[_].step
    step.type == "SbomPolicyEnforcement"
}
