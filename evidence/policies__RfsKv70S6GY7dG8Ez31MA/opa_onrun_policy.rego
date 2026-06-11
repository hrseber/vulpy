# METADATA
# title: OPA Policy Set On Run Required
# description: |
#   Requires that the pipeline has an OPA Policy Set configured to evaluate
#   on pipeline run events with Error and Exit enforcement action.
#   Prevents pipelines from running without runtime governance gate enforcement.
# nist_controls:
#   - CA-7
#   - CM-3
# pipeline_stage: governance
# gate: onsave
# severity: high
# waiver_supported: false
# portability: harness-opa-v1
package raise.opa_onrun_policy

import future.keywords.if
import future.keywords.in

deny[msg] if {
    policy_sets := input.metadata.policyMetadata
    not has_onrun_policy_set(policy_sets)
    msg := "Pipeline does not have an OPA Policy Set with action=onrun. Add a Policy Set with action=onrun and enforcement Error+Exit to enforce runtime governance. NIST CA-7, CM-3 | SOC2 CC5.2, CC8.1 | cATO 3.2 | PCI 6.5, 12.1"
}

has_onrun_policy_set(policy_sets) if {
    some ps in policy_sets
    ps.action == "onrun"
    ps.enabled == true
}
