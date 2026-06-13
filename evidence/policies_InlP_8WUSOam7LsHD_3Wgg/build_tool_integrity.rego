# METADATA
# title: Build Tool Chain Integrity (Tier-1 Digest Pinning)
# description: |
#   All Tier-1 build tools that write to the codebase or produce artifacts
#   (container builders, package installers, IaC providers, AI verify tools,
#   signing tools) MUST use pinned image digests (sha256:) rather than floating
#   version tags (e.g. :latest, :4.0, :main). Unpinned tool images are a
#   SolarWinds-class supply chain risk: a compromised image tag produces
#   malicious artifacts that pass all downstream security scans because
#   the binary content is injected during build, not inserted as a dependency.
#   Personal Docker Hub images in production paths are prohibited.
# nist_controls:
#   - SA-12: Supply Chain Protection
#   - SR-3: Supply Chain Controls
#   - SR-4: Provenance
#   - SR-11: Component Authenticity
#   - SI-7: Software/Firmware Integrity
# pipeline_stage: CI (build), CD (deploy)
# gate: On Save, On Run
# severity: CRITICAL
# waiver_supported: false
# portability: Harness Policy Engine (OPA)
package harness.pipeline.build_tool_integrity

import future.keywords.if
import future.keywords.in

tier1_build_types := {
  "BuildAndPushDockerRegistry", "BuildAndPushECR", "BuildAndPushGCR",
  "BuildAndPushACR", "AiVerify", "Plugin", "Run"
}

personal_hub_pattern := "^[a-z0-9_-]+/[a-z0-9_-]+"
digest_pattern := "@sha256:[a-f0-9]{64}"

# Deny floating tags on AiVerify-type steps (Tier-1 in prod path)
deny[msg] {
  stage := input.pipeline.stages[_].stage
  stage.type == "Deployment"
  env := stage.spec.environment.environmentRef
  env == "prod"
  step := get_all_steps(stage)[_]
  step.type == "AiVerify"
  not contains(step.spec.image, "@sha256:")
  msg := sprintf("FAIL SA-12/SI-7: AiVerify step '%v' in production stage '%v' uses floating image tag '%v'. Must pin to sha256 digest. SolarWinds-class risk: compromised image runs with prod cluster access.", [step.identifier, stage.identifier, step.spec.image])
}

# Deny personal Docker Hub images in production deployment paths
deny[msg] {
  stage := input.pipeline.stages[_].stage
  stage.type == "Deployment"
  env := stage.spec.environment.environmentRef
  env == "prod"
  step := get_all_steps(stage)[_]
  image := step.spec.image
  re_match(`^[a-z0-9][a-z0-9_-]*/[a-z0-9_-]+:`, image)
  not startswith(image, "harness/")
  not startswith(image, "pkg.harness.io/")
  not contains(image, "@sha256:")
  msg := sprintf("FAIL SR-3/SR-4: Step '%v' uses personal/third-party Docker Hub image '%v' in production path without digest pin. Use a verified registry (pkg.harness.io) and pin to sha256.", [step.identifier, image])
}

get_all_steps(stage) := steps {
  steps := {step | step := stage.spec.execution.steps[_].step}
} else := steps {
  steps := {step | 
    group := stage.spec.execution.steps[_].stepGroup
    step := group.steps[_].step
  }
}
