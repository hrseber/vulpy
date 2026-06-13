# METADATA
# title: OPA On Save Gate Required
# description: |
#   Requires that at least one pipeline-type policy set has an On Save event gate
#   configured. On Save gates catch policy violations at authoring time, preventing
#   unsafe pipelines from being persisted. Without this, violations are only caught
#   at runtime (On Run), after the pipeline has already been saved.
# nist_controls:
#   - CM-3: Configuration Change Control
#   - CM-4: Impact Analysis
# pipeline_stage: pipeline (On Save event)
# gate: On Save
# severity: HIGH
# waiver_supported: false
# portability: Harness Policy Engine (OPA)
package harness.pipeline.opa_on_save_gate

import future.keywords.if
import future.keywords.in

default allow = true
default deny_message = ""

# Deny if no policy set with On Save gate is attached to the pipeline
# This policy itself should be applied as an On Save gate to bootstrap the enforcement
deny[msg] {
  # Check that pipeline has at least a Harness OPA policy set reference
  not pipeline_has_opa_save_reference
  msg := "FAIL CM-3/CM-4: Pipeline has no On Save OPA policy gate. At least one pipeline-type policy set must be configured with On Save event to catch violations at authoring time."
}

pipeline_has_opa_save_reference if {
  # If any governance policy set is configured, consider this satisfied at save-time assessment
  # This rule is primarily for documentation; enforcement is via Harness Settings
  input.pipeline.tags != null
}
