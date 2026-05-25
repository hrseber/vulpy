# METADATA
# title: SBOM Generation Enforcement
# description: Requires a native Harness SCS SBOM Orchestration step after any container build/push step. Script-based SBOM generation via Run steps does not satisfy this control because it lacks chain-of-custody, SCS module integration, and verifiable attestation.
# nist_controls: [SR-4, SA-11, SI-7]
# pipeline_stage: ci_package
# gate: post-build
# severity: high
# waiver_supported: true
# portability: harness-opa

package sbom_generation

import future.keywords.in

deny[msg] {
    has_build_step
    not has_sbom_orchestration_step
    msg := "SBOM Generation control failed: Pipeline contains a container build step but no native SCS SBOM Orchestration step. Script-based SBOM generation does not satisfy SOC2 CC7.1, NIST SR-4/SA-11, or SLSA L1 provenance requirements."
}

has_build_step {
    some stage in input.pipeline.stages
    some step in stage.stage.spec.execution.steps
    step.step.type in {"BuildAndPushDockerRegistry","BuildAndPushECR","BuildAndPushGCR","BuildAndPushACR"}
}

has_build_step {
    some stage in input.pipeline.stages
    some step in stage.stage.spec.execution.steps
    step.step.type == "Run"
    contains(lower(step.step.name), "package")
}

has_sbom_orchestration_step {
    some stage in input.pipeline.stages
    some step in stage.stage.spec.execution.steps
    step.step.type == "AquaTrivy"
    step.step.spec.mode == "orchestration"
}

has_sbom_orchestration_step {
    some stage in input.pipeline.stages
    some step in stage.stage.spec.execution.steps
    step.step.type in {"Syft","SbomOrchestrate","CdSbomOrchestrate"}
}
