# METADATA
# title: All maven artifacts have known repository URLs
# description: >-
#   Each Maven package listed in an SBOM must specify the repository URL that it
#   comes from, and that URL must be present in the list of known and permitted
#   Maven repositories. If no URL is specified, the package is assumed to come
#   from Maven Central. Supports both CycloneDX and SPDX formats.
# custom:
#   short_name: urls_known
#   failure_msg: 'Maven repo URL check failed: %s'
#   solution: >-
#     Ensure every maven artifact comes from a known and permitted repository URL,
#     and that the data in the SBOM correctly records that. If using Maven Central,
#     ensure it is included in the allowed list.
#   collections:
#   - redhat
#   - redhat_maven
#   effective_on: "2024-11-10T00:00:00Z"
#
package release.maven_repos

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.sbom.maven

deny contains result if {
	# Ensure policy data exists before running
	count(_rule_data_errors) == 0

	some bad_purl, msg in _repo_url_errors
	result := lib.result_helper_with_term(rego.metadata.chain(), [msg], bad_purl)
}

# --- Internal Helper Logic ---

_repo_url_errors[purl] := msg if {
	some pkg in maven.packages
	purl := pkg.purl

	# Fallback to Maven Central if URL is missing
	source := _get_effective_url(pkg.repository_url)

	not _url_is_permitted(source)

	msg := sprintf("Package %q (source: %q) is not in the permitted list", [purl, source])
}

# Defaulting Logic
_get_effective_url(url) := url if {
	url != ""
} else := "https://repo.maven.apache.org/maven2/"

# Permission Check
_url_is_permitted(url) if {
	permitted := lib.rule_data("allowed_maven_repositories")
	url in permitted
}

# Data Validation
_rule_data_errors contains msg if {
	key := "allowed_maven_repositories"
	not lib.rule_data(key)
	msg := sprintf("Policy data is missing the required %q list", [key])
}
