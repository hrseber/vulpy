# METADATA
# title: Build Tool Chain Integrity - Digest Pinning Required
# description: >
#   Every step that produces or mutates an artifact (container builders, package
#   installers, signing tools) must reference a specific image digest (sha256:...) rather
#   than a floating tag or "latest". Unpinned builder images are the SolarWinds-class
#   attack vector: a compromised registry can silently substitute a malicious build tool
#   that injects backdoors no downstream scan can detect. This control implements SLSA L3
#   build integrity requirements.
# nist_controls:
#   - SA-12
#   - SR-3
#   - SR-4
#   - SR-11
#   - SI-7
# pipeline_stage: CI
# gate: on_save
# severity: CRITICAL
# waiver_supported: false
# portability: harness-opa
package pipeline.build_tool_integrity

import future.keywords.if
import future.keywords.in

_artifact_producing_types := {"BuildAndPushDockerRegistry", "BuildAndPushECR", "BuildAndPushGCR", "BuildAndPushACR"}

deny[msg] if {
    stage := input.pipeline.stages[_].stage
    step := _get_steps(stage)[_]
    stype := _step_type(step)
    stype in _artifact_producing_types
    spec := _step_spec(step)
    not _image_is_digest_pinned(spec)
    msg := sprintf("Artifact-producing step '%v' (type: %v) uses a floating image tag with no digest pin. Pin to sha256 digest to prevent supply chain substitution. NIST SA-12, SR-3, SI-7. SLSA L3.", [_step_name(step), stype])
}

deny[msg] if {
    stage := input.pipeline.stages[_].stage
    step := _get_steps(stage)[_]
    spec := _step_spec(step)
    img := spec.image
    endswith(img, ":latest")
    msg := sprintf("Step '%v' uses ':latest' image tag. Pin to a specific digest or immutable tag. NIST SA-12, SR-3.", [_step_name(step)])
}

_get_steps(stage) := stage.spec.execution.steps
_step_type(step) := step.step.type if step.step
_step_type(step) := step.type if not step.step
_step_name(step) := step.step.name if step.step
_step_name(step) := step.name if not step.step
_step_spec(step) := step.step.spec if step.step
_step_spec(step) := step.spec if not step.step
_image_is_digest_pinned(spec) if contains(spec.image, "@sha256:")
