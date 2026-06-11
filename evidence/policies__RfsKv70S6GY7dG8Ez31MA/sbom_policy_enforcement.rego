# METADATA
# title: SBOM Policy Enforcement Required
# description: |
#   Requires every pipeline that generates an SBOM (contains SscaOrchestration step)
#   to also have an SscaEnforcement step with deny/allow list configuration.
#   Prevents pipelines from generating SBOMs without enforcing component policies.
# nist_controls:
#   - SR-3
#   - SR-11
# pipeline_stage: CI (after SscaOrchestration)
# gate: onsave
# severity: high
# waiver_supported: true
# portability: harness-opa-v1
package raise.sbom_policy_enforcement

import future.keywords.if
import future.keywords.in

deny[msg] if {
    pipeline := input.pipeline
    has_sbom_orchestration(pipeline)
    not has_sbom_enforcement(pipeline)
    msg := "Pipeline has SBOM generation (SscaOrchestration) but no SBOM Policy Enforcement step (SscaEnforcement). Add SscaEnforcement after SscaOrchestration. NIST SR-3, SR-11 | SOC2 CC7.2 | SLSA L2 | PCI 6.3.1"
}

has_sbom_orchestration(pipeline) if {
    some stage in pipeline.stages
    some step in stage.stage.spec.execution.steps
    step.step.type == "SscaOrchestration"
}

has_sbom_enforcement(pipeline) if {
    some stage in pipeline.stages
    some step in stage.stage.spec.execution.steps
    step.step.type == "SscaEnforcement"
}
