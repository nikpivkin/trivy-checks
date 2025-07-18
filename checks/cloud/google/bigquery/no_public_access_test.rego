package builtin.google.bigquery.google0046_test

import rego.v1

import data.builtin.google.bigquery.google0046 as check

test_deny_public_access if {
	inp := {"google": {"bigquery": {"datasets": [{"accessgrants": [{"specialgroup": {"value": "allAuthenticatedUsers"}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_no_public_access if {
	inp := {"google": {"bigquery": {"datasets": [{"accessgrants": [{"specialgroup": {"value": "anotherGroup"}}]}]}}}

	res := check.deny with input as inp
	res == set()
}
