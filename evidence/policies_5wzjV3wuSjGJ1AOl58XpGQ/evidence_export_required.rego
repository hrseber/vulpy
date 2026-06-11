# METADATA
# title: Evidence Export - Scan Results Must Be Persisted
# description: Pipelines must persist scan results, SBOMs, and policy evaluation outputs as
#              auditable evidence artifacts. This is required for cATO continuous ATO maintenance,
#              SOC2 evidence collection, and PCI DSS artifact retention. The presence of an AGR
#              agent step alone does not satisfy this requirement - the pipeline's own scan steps
#              must produce persisted outputs.
# nist_controls: ["CA-2", "CA-7(1)"]
# pipeline_stage: CI
# gate: onsave
# severity: medium
# waiver_supported: true
# portability: harness-opa-v1

package pipeline_raise_evidence_export

deny[msg] {
  has_sto_steps(input.pipeline)
  not has_evidence_persistence(input.pipeline)
  msg := "RAISE Check 14: Pipeline has STO scanner steps but no explicit evidence persistence configuration. Ensure scan results and SBOMs are exported to a durable store (S3, artifact registry, or Harness SCS) for audit trail continuity. Required for cATO and SOC2 evidence collection."
}

has_sto_steps(pipeline) {
  sto_types := {"Semgrep", "Gitleaks", "AquaTrivy", "Owasp", "OsvScanner", "Zap", "SscaOrchestration"}
  step := pipeline.stages[_].stage.spec.execution.steps[_].step
  step.type == sto_types[_]
}

has_evidence_persistence(pipeline) {
  # SscaOrchestration with attestation counts as evidence persistence
  step := pipeline.stages[_].stage.spec.execution.steps[_].step
  step.type == "SscaOrchestration"
  step.spec.attestation.type
}
