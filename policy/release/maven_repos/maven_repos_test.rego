package policy.release.maven_repos_test

import future.keywords.if
import future.keywords.in

import data.lib
import data.policy.release.maven_repos

MOCK_CONFIG := {
	"approved_urls": [
		"https://repo.maven.apache.org/maven2/",
		"https://maven.repository.redhat.com/ga/",
	],
	"warn_urls": ["https://legacy-repo.com/maven2/"],
}

test_unauthorized_url_denied if {
	expected_url := "https://malicious-site.com/repo/pkg.spdx"
	mock_external_refs := [{"externalDocumentId": expected_url}]

	results := maven_repos.deny with data.conforma.release.maven_repos as MOCK_CONFIG
		with data.lib.sbom_spdx.external_document_refs as mock_external_refs

	lib.assert_equal(count(results), 1)
	lib.assert_equal(results[_].term, expected_url)
}

test_warn_url_triggers_warning if {
	expected_url := "https://legacy-repo.com/maven2/pkg.spdx"
	mock_external_refs := [{"externalDocumentId": expected_url}]

	warnings := maven_repos.warn with data.conforma.release.maven_repos as MOCK_CONFIG
		with data.lib.sbom_spdx.external_document_refs as mock_external_refs

	denies := maven_repos.deny with data.conforma.release.maven_repos as MOCK_CONFIG
		with data.lib.sbom_spdx.external_document_refs as mock_external_refs

	lib.assert_equal(count(warnings), 1)
	lib.assert_equal(warnings[_].term, expected_url)

	lib.assert_equal(count(denies), 0)
}

test_approved_url_passes if {
	mock_external_refs := [{"externalDocumentId": "https://repo.maven.apache.org/maven2/pkg.spdx"}]

	denies := maven_repos.deny with data.conforma.release.maven_repos as MOCK_CONFIG
		with data.lib.sbom_spdx.external_document_refs as mock_external_refs

	warnings := maven_repos.warn with data.conforma.release.maven_repos as MOCK_CONFIG
		with data.lib.sbom_spdx.external_document_refs as mock_external_refs

	lib.assert_equal(count(denies), 0)
	lib.assert_equal(count(warnings), 0)
}
