# METADATA
# title: SBOM Policy Enforcement Required
# description: >
#   Every pipeline that generates an SBOM via SscaOrchestration MUST also include
#   an SscaEnforcement step to validate component allow/deny lists. Without enforcement,
#   the SBOM is generated but never acted upon, leaving dependency risk unmitigated.
# nist_controls:
#   - SR-3
#   - SR-11
#   - RA-5
# pipeline_stage: CI
# gate: on_save
# severity: HIGH
# waiver_supported: false
# portability: harness-opa
package pipeline.sbom_policy_enforcement

import future.keywords.if
import future.keywords.in

deny[msg] if {
    has_ssca_orchestration
    not has_ssca_enforcement
    msg := "Pipeline generates an SBOM (SscaOrchestration) but has no SscaEnforcement step. Add an SscaEnforcement step after SscaOrchestration to validate component policy. NIST SR-3, SR-11, RA-5."
}

has_ssca_orchestration if {
    stage := input.pipeline.stages[_].stage
    step := stage.spec.execution.steps[_]
    _step_type(step) == "SscaOrchestration"
}

has_ssca_enforcement if {
    stage := input.pipeline.stages[_].stage
    step := stage.spec.execution.steps[_]
    _step_type(step) == "SscaEnforcement"
}

_step_type(step) := step.step.type if step.step
_step_type(step) := step.type if not step.step
