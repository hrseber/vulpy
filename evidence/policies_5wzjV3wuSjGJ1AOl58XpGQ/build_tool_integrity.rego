# METADATA
# title: Build Tool Chain Integrity - No Floating Image Tags
# description: Every step that builds, packages, or pushes container images must use a pinned
#              image reference (digest or explicit non-latest tag). Floating tags like 'latest'
#              are SolarWinds-class risk: a compromised image registry can inject malicious code
#              that no downstream scan can detect because the build itself is the attack vector.
# nist_controls: ["SA-12", "SR-3", "SR-4", "SR-11", "SI-7"]
# pipeline_stage: CI
# gate: onsave
# severity: critical
# waiver_supported: false
# portability: harness-opa-v1

package pipeline_raise_build_tool_integrity

import future.keywords.in

build_types := {"BuildAndPushDockerRegistry", "BuildAndPushECR", "BuildAndPushGCR", "BuildAndPushACR", "Run", "Plugin"}

deny[msg] {
  step := input.pipeline.stages[_].stage.spec.execution.steps[_].step
  step.type in build_types
  img := step.spec.image
  is_floating_tag(img)
  msg := sprintf("RAISE Check 15: Step '%v' (type: %v) uses image '%v' with a floating or unpinned tag. Pin to a specific digest (sha256:...) or immutable version tag. Floating tags allow silent image substitution — a SolarWinds-class build chain attack vector.", [step.name, step.type, img])
}

is_floating_tag(img) {
  endswith(img, ":latest")
}

is_floating_tag(img) {
  not contains(img, ":")
}

is_floating_tag(img) {
  not contains(img, "@sha256:")
  parts := split(img, ":")
  count(parts) == 2
  tag := parts[1]
  tag == "latest"
}
