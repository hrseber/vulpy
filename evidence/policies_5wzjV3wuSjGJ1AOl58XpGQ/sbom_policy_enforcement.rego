# METADATA
# title: SBOM Policy Enforcement Required
# description: Requires an SscaEnforcement step after every SBOM Orchestration step in CI pipelines.
#              Blocks pipelines that generate an SBOM but do not enforce allow/deny component policy.
# nist_controls: ["SR-3", "SR-11", "SA-11"]
# pipeline_stage: CI
# gate: onsave
# severity: high
# waiver_supported: true
# portability: harness-opa-v1

package pipeline_raise_sbom_policy_enforcement

import future.keywords.every
import future.keywords.in

deny[msg] {
  input.pipeline.stages[_].stage.type == "CI"
  steps := get_all_steps(input.pipeline)
  has_sbom_orchestration(steps)
  not has_sbom_enforcement(steps)
  msg := "RAISE Check 2: Pipeline generates SBOM (SscaOrchestration) but has no SBOM Policy Enforcement (SscaEnforcement) step. Add an SscaEnforcement step with deny/allow lists after SBOM generation."
}

has_sbom_orchestration(steps) {
  steps[_].type == "SscaOrchestration"
}

has_sbom_enforcement(steps) {
  steps[_].type == "SscaEnforcement"
}

get_all_steps(pipeline) = steps {
  steps := [s | s := pipeline.stages[_].stage.spec.execution.steps[_].step]
}
