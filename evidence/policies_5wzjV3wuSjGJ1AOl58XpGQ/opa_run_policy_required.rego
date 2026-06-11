# METADATA
# title: OPA Policy Set on Run Event Required
# description: Requires at least one enabled policy set configured with action=onrun and error+exit
#              behavior attached to every pipeline in scope. Ensures governance cannot be bypassed
#              by running a pipeline that was never saved through an onsave gate.
# nist_controls: ["CA-7", "CM-3"]
# pipeline_stage: governance
# gate: onsave
# severity: high
# waiver_supported: false
# portability: harness-opa-v1

package pipeline_raise_opa_run_required

deny[msg] {
  # Evaluated at pipeline-save time via Harness Policy Engine
  # The policy set list is injected by the evaluator as input.policy_sets
  policy_sets := input.policy_sets
  not any_onrun_policy(policy_sets)
  msg := "RAISE Check 9: No OPA policy set with action=onrun is attached to this pipeline. A governance policy set must evaluate on every pipeline run with Error and Exit behavior to enforce RAISE 2.0 gates at execution time, not just at save time."
}

any_onrun_policy(sets) {
  sets[_].action == "onrun"
  sets[_].enabled == true
}
