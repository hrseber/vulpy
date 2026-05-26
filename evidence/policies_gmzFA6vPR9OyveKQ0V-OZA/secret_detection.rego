# METADATA
# title: Secret Detection Enforcement — CRITICAL
# description: Requires a Gitleaks or equivalent STO secrets scanner step in every pipeline. Absence of secret detection is a CRITICAL control gap — any credentials committed to source code will ship undetected through all downstream stages.
# nist_controls: [IA-5, SC-28]
# pipeline_stage: ci_build
# gate: pre-scan
# severity: critical
# waiver_supported: false
# portability: harness-opa

package secret_detection

import future.keywords.in

deny[msg] {
    not has_secret_scan_step
    msg := "CRITICAL: No secret detection step found. A Gitleaks, TruffleHog, or equivalent STO secrets scanner is required in all pipelines. Violates SOC2 CC6.1/CC6.7, NIST IA-5/SC-28, cATO 1.0 CONMON, PCI 8.2/8.6. Secrets committed to source code will never be detected by this pipeline."
}

has_secret_scan_step {
    some stage in input.pipeline.stages
    some step in stage.stage.spec.execution.steps
    step.step.type in {"Gitleaks","TruffleHog","GitLeaks"}
}

has_secret_scan_step {
    some stage in input.pipeline.stages
    some step in stage.stage.spec.execution.steps
    step.step.type == "Security"
    step.step.spec.type in {"Gitleaks","TruffleHog"}
}

has_secret_scan_step {
    some stage in input.pipeline.stages
    some step in stage.stage.spec.execution.steps
    step.step.type == "CustomIngest"
    contains(lower(step.step.spec.config.tool), "gitleaks")
}
