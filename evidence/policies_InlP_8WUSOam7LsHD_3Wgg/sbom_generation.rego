# METADATA
# title: SBOM Generation Required After Build/Push
# description: |
#   Any pipeline that contains a container build and push step MUST also contain
#   an SscaOrchestration step (SBOM generation) with attestation enabled (cosign
#   or SLSA provenance) AFTER the build/push. Without an attested SBOM, there
#   is no verifiable record of what components were included in the artifact,
#   making supply chain audits impossible.
# nist_controls:
#   - SR-4: Provenance
#   - SA-11: Developer Security Testing
# pipeline_stage: CI (after build/push)
# gate: On Save, On Run
# severity: HIGH
# waiver_supported: false
# portability: Harness Policy Engine (OPA)
package harness.pipeline.sbom_generation

import future.keywords.if
import future.keywords.in

build_push_types := {
  "BuildAndPushDockerRegistry", "BuildAndPushECR", "BuildAndPushGCR", "BuildAndPushACR"
}

# Check if pipeline has a build/push step
has_build_push if {
  stage := input.pipeline.stages[_].stage
  stage.type == "CI"
  step := stage.spec.execution.steps[_].step
  step.type in build_push_types
}

# Check if pipeline has an SBOM orchestration step
has_sbom_step if {
  stage := input.pipeline.stages[_].stage
  stage.type == "CI"
  group := stage.spec.execution.steps[_].stepGroup
  step := group.steps[_].step
  step.type == "SscaOrchestration"
  step.spec.mode == "generation"
}

# Check if SBOM step has attestation
has_attestation if {
  stage := input.pipeline.stages[_].stage
  stage.type == "CI"
  group := stage.spec.execution.steps[_].stepGroup
  step := group.steps[_].step
  step.type == "SscaOrchestration"
  step.spec.attestation.type != ""
}

deny[msg] {
  has_build_push
  not has_sbom_step
  msg := "FAIL SR-4/SA-11: Pipeline has a container build/push step but no SscaOrchestration SBOM generation step. Add an SscaOrchestration step (mode: generation) after the build/push step in the CI stage."
}

deny[msg] {
  has_build_push
  has_sbom_step
  not has_attestation
  msg := "FAIL SR-4/SA-11: SBOM generation step exists but attestation is not configured. Add attestation (type: cosign) with a valid private key to produce a verifiable SBOM attestation."
}
