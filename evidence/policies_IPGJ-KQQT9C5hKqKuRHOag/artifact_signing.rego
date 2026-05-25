# METADATA
# title: Require Artifact Signing (cosign / SLSA Provenance)
# description: >
#   Requires that any container image built by the pipeline is signed using
#   cosign (keyless or key-based) or equivalent SLSA provenance attestation.
#   Unsigned artifacts cannot be verified at deployment time and violate
#   DoD cATO 3.1 supply-chain integrity requirements.
#   NOTE: This pipeline uses a custom ci-sign script rather than a native
#   Harness SbomOrchestration attestation step. The ci_sign stage is
#   conditionally skipped for terraform language. A native SbomOrchestration
#   step with attestation enabled is preferred over a custom signing script
#   because it integrates with Harness SCS chain-of-custody.
# nist_controls:
#   - SI-7   (Software, Firmware, and Information Integrity)
#   - SA-12  (Supply Chain Protection)
# pipeline_stage: ci_sign (after ci_package)
# gate: On Run — Error and Exit
# severity: high
# waiver_supported: true
# portability: Harness SCS (pipeline_v1 / v0)

package artifact_signing

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny contains msg if {
    builds_container
    not signing_present
    msg := sprintf(
        "Pipeline '%v' builds a container image but has no signing step with attestation. Add an SbomOrchestration step with attestation enabled (cosign-keyless preferred) to satisfy SI-7, SA-12, SLSA L2-L3, and cATO 3.1.",
        [input.pipeline.identifier]
    )
}

builds_container if {
    stage := input.pipeline.stages[_].stage
    step  := stage.spec.execution.steps[_].step
    step.type == "Run"
    contains(lower(step.spec.image), "kaniko")
}

# Custom ci-sign script counts as signing if present and not always skipped
signing_present if {
    stage := input.pipeline.stages[_].stage
    stage.identifier == "ci_sign"
    # Stage is not unconditionally disabled
    not always_skipped(stage)
}

signing_present if {
    stage := input.pipeline.stages[_].stage
    step  := stage.spec.execution.steps[_].step
    step.type == "SbomOrchestration"
    step.spec.attestations  # attestation block must be present
}

always_skipped(stage) if {
    stage.when.condition == "false"
}
