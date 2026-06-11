# METADATA
# title: Build Tool Chain Integrity - Digest Pinning
# description: |
#   Requires all pipeline steps that write to the codebase or produce artifacts
#   (Run steps, container builders, signing tools) to reference container images
#   by digest (sha256@) rather than floating tags (latest, alpine, semver-only).
#   Prevents SolarWinds-class supply chain attacks where the build tool itself is
#   compromised at a registry level. Tier 1 (compilers/builders) and Tier 2
#   (signing tools: cosign, Syft) must both be pinned.
# nist_controls:
#   - SA-12
#   - SR-3
#   - SR-4
#   - SR-11
#   - SI-7
# pipeline_stage: CI (build/artifact-producing steps)
# gate: onsave
# severity: critical
# waiver_supported: false
# portability: harness-opa-v1
package raise.build_tool_integrity

import future.keywords.if
import future.keywords.in

deny[msg] if {
    some stage in input.pipeline.stages
    stage.stage.type in {"CI", "SecurityTests"}
    some step in stage.stage.spec.execution.steps
    step.step.type == "Run"
    img := step.step.spec.image
    not contains(img, "@sha256:")
    msg := sprintf("Run step '%v' uses image '%v' without digest pin. Replace with image@sha256:<digest>. SolarWinds-class risk: compromised builder injects malicious code downstream scans cannot detect. NIST SA-12, SR-3, SI-7 | SLSA L3 | PCI 6.2", [step.step.name, img])
}

deny[msg] if {
    some stage in input.pipeline.stages
    stage.stage.type == "CI"
    some step in stage.stage.spec.execution.steps
    step.step.type == "BuildAndPushDockerRegistry"
    not step.step.spec.builderImage
    msg := sprintf("BuildAndPushDockerRegistry step '%v' uses Harness default builder without explicit digest-pinned builderImage. Specify builderImage: <image>@sha256:<digest>. NIST SA-12 | SOC2 CC8.1 | SLSA L3", [step.step.name])
}
