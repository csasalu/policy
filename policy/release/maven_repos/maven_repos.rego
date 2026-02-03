# METADATA
# title: All maven artifacts have known repository URLs
# description: >-
#   Each Maven package listed in an SBOM must specify the repository URL that it
#   comes from, and that URL must be present in the list of known and permitted
#   Maven repositories. If no URL is specified, the package is assumed to come
#   from Maven Central.
# custom:
#   short_name: urls_known
#   failure_msg: 'Maven repo URL check failed: %s'
#   solution: >-
#     Ensure every maven artifact comes from a known and permitted repository URL.
#   collections:
#   - redhat
#   - redhat_maven
#   effective_on: "2026-05-10T00:00:00Z"
#
package release.maven_repos

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.sbom.maven

# METADATA
# title: Missing Policy Data
# scope: rule
# custom:
#    short_name: policy_data_missing
#    failure_msg: 'Policy data is missing the required %q list'
deny contains result if {
	some key in _rule_data_errors
	result := lib.result_helper(rego.metadata.chain(), [key])
}

# METADATA
# title: Known Repository URLs
# scope: rule
# custom:
#    short_name: urls_known
#    failure_msg: '%s'
deny contains result if {
	some purl, msg in _repo_url_errors
	base := lib.result_helper(rego.metadata.chain(), [msg])
	result := object.union(base, {"term": purl})
}

_repo_url_errors[purl] := msg if {
	some pkg in maven.packages
	purl := pkg.purl
	source := _get_effective_url(pkg.repository_url)
	not _url_is_permitted(source)
	msg := sprintf("Package %q (source: %q) is not in the permitted list", [purl, source])
}

_get_effective_url(url) := url if {
	url != ""
} else := "https://repo.maven.apache.org/maven2/"

_url_is_permitted(url) if {
	permitted := lib.rule_data("allowed_maven_repositories")
	url in permitted
}

_rule_data_errors contains key if {
	key := "allowed_maven_repositories"
	data_list := object.get(data.rule_data, key, "UNDEFINED_IN_DATA")
	_is_invalid_data(data_list)
}

_is_invalid_data(val) if {
	val == "UNDEFINED_IN_DATA"
	print("") # workaround for code coverage
}

_is_invalid_data(val) if not is_array(val)

_is_invalid_data(val) if {
	is_array(val)
	count(val) == 0
}
