# METADATA
# title: Require SBOM Generation (SbomOrchestration)
# description: >
#   Enforces that every CI pipeline that builds or pushes a container image
#   includes a Harness SCS SbomOrchestration step immediately after the build/push.
#   Without a machine-readable SBOM, downstream vulnerability correlation,
#   policy enforcement, and cATO artifact attestation are impossible.
# nist_controls:
#   - SR-4   (Provenance)
#   - SA-11  (Developer Testing and Evaluation)
# pipeline_stage: ci_package (after BuildAndPush)
# gate: On Run — Error and Exit
# severity: high
# waiver_supported: true
# portability: Harness SCS (pipeline_v1 / v0)

package sbom_generation

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny contains msg if {
    # Walk every step in every stage looking for a container build
    stage := input.pipeline.stages[_].stage
    step  := stage.spec.execution.steps[_].step
    build_step_types := {"BuildAndPushDockerRegistry", "BuildAndPushECR", "BuildAndPushGAR", "BuildAndPushACR"}
    step.type in build_step_types

    # Confirm no SbomOrchestration step exists anywhere in the pipeline
    not sbom_step_exists
    msg := sprintf(
        "Pipeline '%v' builds a container image (step '%v' in stage '%v') but has no SbomOrchestration step. Add an SCS SbomOrchestration step after the build/push to satisfy SR-4 and SLSA L1.",
        [input.pipeline.identifier, step.identifier, stage.identifier]
    )
}

# Also flag script-based kaniko builds (ci_package pattern)
deny contains msg if {
    stage := input.pipeline.stages[_].stage
    step  := stage.spec.execution.steps[_].step
    step.type == "Run"
    contains(lower(step.spec.image), "kaniko")
    not sbom_step_exists
    msg := sprintf(
        "Pipeline '%v' uses a kaniko Run step for container builds (stage '%v') but has no SbomOrchestration step. Add an SCS SbomOrchestration step to satisfy SR-4 and SLSA L1.",
        [input.pipeline.identifier, stage.identifier]
    )
}

sbom_step_exists if {
    stage := input.pipeline.stages[_].stage
    step  := stage.spec.execution.steps[_].step
    step.type == "SbomOrchestration"
}
