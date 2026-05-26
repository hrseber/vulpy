# METADATA
# title: Artifact Signing and Attestation Enforcement
# description: Requires cosign or SLSA provenance attestation on all container artifacts. Signing must produce a verifiable attestation chain anchored to the build. A skippable Run step invoking a sign script is insufficient — the signing stage must be non-optional for production builds.
# nist_controls: [SI-7, SA-12, SR-4]
# pipeline_stage: ci_sign
# gate: post-package
# severity: high
# waiver_supported: true
# portability: harness-opa

package artifact_signing

import future.keywords.in

deny[msg] {
    has_container_build
    not has_non_skippable_signing
    msg := "Artifact signing control failed: Pipeline produces container artifacts but signing stage has a skip condition or uses a skippable Run step. For production builds, signing must be non-optional. SOC2 CC6.1, NIST SI-7/SA-12, SLSA L2-L3."
}

deny[msg] {
    input.artifact.signature_verified == false
    msg := "Artifact signing verification failed: Signature on produced artifact could not be verified. Ensure cosign public key is accessible and the attestation was uploaded."
}

has_container_build {
    some stage in input.pipeline.stages
    stage.stage.type == "CI"
    some step in stage.stage.spec.execution.steps
    step.step.type == "Run"
    contains(lower(step.step.name), "package")
}

has_non_skippable_signing {
    some stage in input.pipeline.stages
    stage.stage.type == "CI"
    some step in stage.stage.spec.execution.steps
    contains(lower(step.step.name), "sign")
    not stage.stage.when
}
