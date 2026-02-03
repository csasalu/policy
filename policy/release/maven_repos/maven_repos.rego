package policy.release.maven_repos

import data.lib
import data.lib.sbom_spdx
import future.keywords.if
import future.keywords.in

# METADATA
# title: Maven SPDX SBOM Source Verification (Strict)
# description: >-
#   Enforces a strict allow-list for Maven repositories.
#   Only URLs in the approved or warn lists are permitted.
# custom:
#   short_name: maven_spdx_strict_check
#   failure_msg: "SBOM references an unauthorized source: %s"
#   solution: >-
#     The repository used is not on the authorized list. Please use
#     internal mirrors or request the URL be added to the allowed list.
#   collections:
#     - redhat_maven
#   severity: failure

deny contains result if {
	some ref in sbom_spdx.external_document_refs
	url := ref.externalDocumentId

	not _is_approved(url)
	not _is_in_warn_list(url)

	msg := sprintf("CRITICAL: Source %q is unauthorized. It is not in the approved or warn lists.", [url])
	result := lib.result_helper_with_term(rego.metadata.chain(), [msg], url)
}

# METADATA
# title: Maven SPDX SBOM Source Verification (Warn)
# description: >-
#   Identifies Maven repositories that are permitted but discouraged.
#   These sources should be migrated to an approved internal mirror.
# custom:
#   short_name: maven_spdx_unverified_check
#   failure_msg: "SBOM references an unverified source: %s"
#   solution: >-
#     The repository used is on the warn list. Please plan to migrate
#     this dependency to an approved internal mirror.
#   collections:
#     - redhat_maven
#   severity: warning

warn contains result if {
	some ref in sbom_spdx.external_document_refs
	url := ref.externalDocumentId

	_is_in_warn_list(url)

	# We don't warn if it's already approved (though lists should be distinct)
	not _is_approved(url)

	msg := sprintf("WARNING: Source %q is on the monitored 'warn' list. Please migrate to an approved mirror.", [url])
	result := lib.result_helper_with_term(rego.metadata.chain(), [msg], url)
}

_is_approved(url) if {
	some approved_url in data.conforma.release.maven_repos.approved_urls
	startswith(url, approved_url)
}

_is_in_warn_list(url) if {
	some warn_url in data.conforma.release.maven_repos.warn_urls
	startswith(url, warn_url)
}
