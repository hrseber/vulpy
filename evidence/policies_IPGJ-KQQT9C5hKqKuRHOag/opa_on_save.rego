# METADATA
# title: Require OPA Policy Set — On Save Gate
# description: >
#   Requires that the pipeline is associated with at least one OPA policy set
#   configured with the "On Save" event (pipeline_type = "pipeline").
#   On-Save gates catch structural violations — missing required stages, wrong
#   deployment strategy, missing approval gates — at authoring time before any
#   execution occurs. Without On-Save enforcement, a pipeline author can remove
#   required controls and the gap will not be detected until the next run.
#   The gate_pipeline_structure policy set in this project is DISABLED.
# nist_controls:
#   - CM-3   (Configuration Change Control)
#   - CM-4   (Impact Analyses)
# pipeline_stage: N/A — fires on pipeline save event
# gate: On Save — Error and Exit
# severity: medium
# waiver_supported: false
# portability: Harness OPA (account / org / project scope)

package opa_on_save

import future.keywords.contains
import future.keywords.if

# This policy is evaluated as an On-Save gate itself.
# It checks that at least one other enabled On-Save policy set exists
# that covers structural pipeline controls.
deny contains msg if {
    # If this policy is reached, on-save is wired up for this policy set.
    # Verify that gate_pipeline_structure or equivalent is enabled.
    enabled_onsave_sets := [ps | ps := input.account.policy_sets[_]; ps.type == "pipeline"; ps.enabled == true]
    count(enabled_onsave_sets) == 0
    msg := "No enabled On-Save (type=pipeline) policy set is active for this project. Enable 'gate_pipeline_structure' or an equivalent On-Save policy set to satisfy CM-3/CM-4 and SOC2 CC8.1."
}
