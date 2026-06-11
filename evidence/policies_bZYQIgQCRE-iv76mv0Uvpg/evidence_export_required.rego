# METADATA
# title: Scan Results and SBOMs Must Be Persisted as Evidence
# description: >
#   A compliant pipeline must explicitly persist security scan results, SBOM artifacts,
#   and policy evaluation outputs as versioned, retrievable evidence. Relying solely on
#   transient step logs does not satisfy audit chain-of-custody requirements for SOC2,
#   NIST CA-2/CA-7(1), SLSA L2, or cATO 1.0. Add explicit file store uploads, artifact
#   registry pushes, or S3/GCS bucket writes for SBOM JSON and scan result exports.
# nist_controls:
#   - CA-2
#   - CA-7
# pipeline_stage: CI
# gate: on_save
# severity: MEDIUM
# waiver_supported: true
# portability: harness-opa
package pipeline.evidence_export_required

import future.keywords.if

_evidence_step_types := {"S3Upload", "GCSUpload", "ArtifactUpload", "SaveCacheGCS", "SaveCacheS3"}

deny[msg] if {
    has_scanner_steps
    not has_evidence_export
    msg := "Pipeline runs security scanners but has no explicit evidence export step (e.g., S3Upload, GCSUpload, ArtifactUpload). Add a step to persist SBOM JSON and scan results as versioned artifacts. NIST CA-2, CA-7(1)."
}

has_scanner_steps if {
    stage := input.pipeline.stages[_].stage
    step := stage.spec.execution.steps[_]
    t := _step_type(step)
    t in {"Semgrep","AquaTrivy","Gitleaks","Owasp","OsvScanner","Zap","SscaOrchestration"}
}

has_evidence_export if {
    stage := input.pipeline.stages[_].stage
    step := stage.spec.execution.steps[_]
    _step_type(step) in _evidence_step_types
}

_step_type(step) := step.step.type if step.step
_step_type(step) := step.type if not step.step
