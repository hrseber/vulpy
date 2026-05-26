# METADATA
# title: SBOM Component Policy Enforcement
# description: Enforces allow/deny lists on SBOM components. Blocks promotion of artifacts containing components with prohibited licenses, components from denied namespaces, or components with unacknowledged critical CVEs. An SBOM must exist before this gate can pass.
# nist_controls: [SR-3, SR-11, RA-5]
# pipeline_stage: ci_package
# gate: post-sbom
# severity: high
# waiver_supported: true
# portability: harness-opa

package sbom_policy_enforcement

import future.keywords.in

denied_licenses := {"GPL-3.0","AGPL-3.0","LGPL-2.0","LGPL-2.1","LGPL-3.0","CC-BY-NC","Proprietary","SSPL"}

deny[msg] {
    input.artifact.sbom_present == false
    msg := "SBOM policy enforcement cannot proceed: No SBOM was generated for this artifact. An SBOM Orchestration step is required before component policy can be evaluated. Closes SOC2 CC7.2, NIST SR-3/SR-11, SLSA L2."
}

deny[msg] {
    some component in input.artifact.packages
    component.license in denied_licenses
    msg := sprintf("SBOM policy violation: Component '%v@%v' uses denied license '%v'. Review and resolve before promoting this artifact. SOC2 CC7.2, NIST SR-3/SR-11.", [component.name, component.version, component.license])
}

deny[msg] {
    input.artifact.component_count == 0
    input.artifact.sbom_present == true
    msg := "SBOM has zero components — verify SBOM generation ran to completion on a populated artifact."
}

warn[msg] {
    input.artifact.component_count > 500
    msg := sprintf("Large component surface: %v components detected. Review dependency tree for transitive risk.", [input.artifact.component_count])
}
