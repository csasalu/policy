package release.maven_repos

import data.lib
import future.keywords.if

# Mock data for permitted repositories
mock_data := {"allowed_maven_repositories": [
	"https://repo.maven.apache.org/maven2/",
	"https://maven.repository.redhat.com/ga/",
]}

# Test 1: CycloneDX package from a permitted repository passes
test_cyclonedx_permitted if {
	cdx_input := [{"purl": "pkg:maven/org.apache/log4j@2.17.1", "externalRefs": [{"type": "distribution", "url": "https://repo.maven.apache.org/maven2/"}]}]

	lib.assert_empty(deny) with data.rule_data as mock_data
		with data.lib.cyclonedx.packages as cdx_input
}

# Test 2: SPDX package from a permitted repository passes
test_spdx_permitted if {
	spdx_input := [{"purl": "pkg:maven/com.redhat/example@1.0", "externalRefs": [{"referenceType": "distribution", "referenceLocator": "https://maven.repository.redhat.com/ga/"}]}]

	lib.assert_empty(deny) with data.rule_data as mock_data
		with data.lib.spdx.packages as spdx_input
}

# Test 3: Missing URL defaults to Maven Central (Passes if Central is allowed)
test_default_maven_central_pass if {
	# No externalRefs provided
	cdx_input := [{"purl": "pkg:maven/org.base/no-url@1.0", "externalRefs": []}]

	lib.assert_empty(deny) with data.rule_data as mock_data
		with data.lib.cyclonedx.packages as cdx_input
}

# Test 4: Missing URL fails if Maven Central is NOT in the allowed list
test_default_maven_central_fail if {
	restricted_data := {"allowed_maven_repositories": ["https://internal.repo/"]}
	cdx_input := [{"purl": "pkg:maven/org.base/no-url@1.0", "externalRefs": []}]

	expected := {{
		"code": "urls_known",
		"msg": "Package \"pkg:maven/org.base/no-url@1.0\" (source: \"https://repo.maven.apache.org/maven2/\") is not in the permitted list",
		"term": "pkg:maven/org.base/no-url@1.0",
	}}

	lib.assert_equal(deny, expected) with data.rule_data as restricted_data
		with data.lib.cyclonedx.packages as cdx_input
}

# Test 5: Explicitly unpermitted repository fails
test_unpermitted_url_fail if {
	cdx_input := [{"purl": "pkg:maven/bad/actor@6.6.6", "externalRefs": [{"type": "distribution", "url": "https://malicious.net/m2"}]}]

	expected := {{
		"code": "urls_known",
		"msg": "Package \"pkg:maven/bad/actor@6.6.6\" (source: \"https://malicious.net/m2\") is not in the permitted list",
		"term": "pkg:maven/bad/actor@6.6.6",
	}}

	lib.assert_equal(deny, expected) with data.rule_data as mock_data
		with data.lib.cyclonedx.packages as cdx_input
}

# Test 6: Policy fails if rule data is missing
test_missing_rule_data if {
	lib.assert_equal(deny, {{
		"code": "maven_repos._rule_data_errors",
		"msg": "Policy data is missing the required \"allowed_maven_repositories\" list",
	}}) with data.rule_data as {}
}
