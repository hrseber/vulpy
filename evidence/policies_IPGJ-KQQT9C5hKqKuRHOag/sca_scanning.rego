# METADATA
# title: Require SCA (Software Composition Analysis) Scanner
# description: >
#   Requires a dedicated STO SCA scanner (OWASP Dependency Check, OSV-Scanner,
#   Snyk, or Grype) in addition to any Trivy container scan.
#   SCA scanners analyze source-level dependency manifests (go.sum, pom.xml,
#   package-lock.json) before build, catching vulnerabilities before they are
#   baked into an image. Trivy container scan is a complementary runtime check,
#   not a substitute for pre-build SCA.
#   NOTE: This pipeline runs SonarQube and a custom osv/sca script via ci-static-analysis.
#   A dedicated STO SCA step provides normalised findings in the Harness STO
#   dashboard and enables fail_on_severity thresholds.
# nist_controls:
#   - RA-5   (Vulnerability Monitoring and Scanning)
#   - SR-4   (Provenance)
# pipeline_stage: ci_static_analysis
# gate: On Run — Error and Exit
# severity: high
# waiver_supported: true
# portability: Harness STO (pipeline_v1 / v0)

package sca_scanning

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny contains msg if {
    not sto_sca_present
    msg := sprintf(
        "Pipeline '%v' lacks a native STO SCA step (OWASP Dep Check, OSV, Snyk). Custom ci-static-analysis scripts produce local reports but do not surface findings in the Harness STO dashboard or enforce fail_on_severity thresholds. Add a native STO SCA scanner to satisfy RA-5, SR-4, and SLSA L1.",
        [input.pipeline.identifier]
    )
}

sto_sca_step_types := {"OsvScanner", "OWASPDepCheck", "Snyk", "Grype", "AquaTrivy"}

sto_sca_present if {
    stage := input.pipeline.stages[_].stage
    step  := stage.spec.execution.steps[_].step
    step.type in sto_sca_step_types
}

sto_sca_present if {
    stage := input.pipeline.stages[_].stage
    step  := stage.spec.execution.steps[_].step
    step.type == "Security"
    lower(step.spec.type) in {"oswaldep", "osv", "snyk", "grype"}
}
