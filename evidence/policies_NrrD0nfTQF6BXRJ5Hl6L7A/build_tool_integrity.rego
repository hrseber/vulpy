# METADATA
# title: Build Tool Chain Integrity — Digest Pinning
# description: All Tier 1 build tools (compilers, container builders, package installers) and Tier 2 artifact signers must reference container images by SHA256 digest, not by mutable version tags or floating tags. This prevents SolarWinds-class attacks where the build tool itself is compromised after a tag mutation.
# nist_controls: [SA-12, SR-3, SR-4, SR-11, SI-7]
# pipeline_stage: all
# gate: on-save
# severity: critical
# waiver_supported: false
# portability: harness-opa

package build_tool_integrity

import future.keywords.in

tier1_keywords := {"kaniko","golang","maven","dotnet","node","python","terraform","rust-ci","jdk","openjdk","eclipse-temurin"}
tier2_keywords := {"cosign","syft","sbom","slsa","rekor"}
floating_tags := {"latest","stable","main","master","current","edge","nightly","release","lts"}

deny[msg] {
    some stage in input.pipeline.stages
    some step in stage.stage.spec.execution.steps
    image := step.step.spec.image
    is_tier1_or_tier2(image)
    not has_digest(image)
    msg := sprintf("Build tool integrity violation: Tier 1/2 image '%v' in step '%v' lacks @sha256 digest pinning. A registry tag mutation or supply chain compromise can inject malicious code before any scan can detect it. Pin to digest. NIST SA-12/SR-3/SR-4/SR-11/SI-7, SLSA L3, PCI 6.2.", [image, step.step.name])
}

deny[msg] {
    some stage in input.pipeline.stages
    some step in stage.stage.spec.execution.steps
    image := step.step.spec.image
    tag := get_tag(image)
    tag in floating_tags
    msg := sprintf("Build tool integrity violation: Image '%v' in step '%v' uses floating tag ':%v'. This is unconditionally denied for build tools. Pin to a specific version and add @sha256 digest.", [image, step.step.name, tag])
}

is_tier1_or_tier2(image) {
    some kw in tier1_keywords
    contains(lower(image), kw)
}

is_tier1_or_tier2(image) {
    some kw in tier2_keywords
    contains(lower(image), kw)
}

has_digest(image) {
    contains(image, "@sha256:")
}

get_tag(image) := tag {
    parts := split(image, ":")
    count(parts) >= 2
    tag_with_digest := parts[count(parts) - 1]
    tag := split(tag_with_digest, "@")[0]
}
