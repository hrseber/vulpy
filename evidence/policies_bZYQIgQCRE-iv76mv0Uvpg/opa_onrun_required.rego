# METADATA
# title: OPA Policy Set Must Evaluate on Pipeline Run
# description: >
#   A compliant pipeline must have an OPA Policy Set configured with action=onrun
#   (On Pipeline Run, Error and Exit). Policy evaluation only on save (onsave) does not
#   prevent runtime violations introduced by dynamic inputs, override flags, or changes
#   made between save and run. Both onsave AND onrun gates are required for full coverage.
# nist_controls:
#   - CA-7
#   - CM-3
# pipeline_stage: governance
# gate: on_run
# severity: HIGH
# waiver_supported: false
# portability: harness-opa
package pipeline.opa_onrun_required

import future.keywords.if

deny[msg] if {
    not has_onrun_policy_set
    msg := "No OPA Policy Set with action=onrun is attached to this pipeline. Add a Policy Set configured for On Pipeline Run (Error and Exit) to enforce runtime governance. NIST CA-7, CM-3."
}

# Note: This policy requires external context about policy set configuration.
# For automated validation, inject policy_sets array into input from Harness governance metadata.
has_onrun_policy_set if {
    ps := input.governance.policy_sets[_]
    ps.action == "onrun"
    ps.enabled == true
}
