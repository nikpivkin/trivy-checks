package custom.regal.rules.custom["custom-data-import-prefix_test"]

import rego.v1

import data.custom.regal.rules.assert
import data.custom.regal.rules.custom["custom-data-import-prefix"] as rule

test_import_path_id_mismatch if {
	module := regal.parse_module("example.rego", `# METADATA
# custom:
#   id: TEST-001
package policy

import data.wrongprefix.foo

foo := true`)

	r := rule.report with input as module

	expected := {{
		"category": "custom",
		"description": "Custom data import paths must follow the format `data.<custom_id>.*`,\nFor example, for the ID TEST-001, a valid import path would be `data.test001.<...>`.\n",
		"level": "error",
		"location": {
			"col": 1, "end": {"col": 17, "row": 3},
			"file": "example.rego",
			"row": 1,
			"text": "# METADATA",
		},
		"title": "custom-data-import-prefix",
	}}
	assert.eq(expected, r)
}

test_import_path_id_match if {
	module := regal.parse_module("example.rego", `# METADATA
# custom:
#   id: TEST-001
package policy

import data.test001.foo

foo := true`)

	r := rule.report with input as module

	assert.eq(set(), r)
}
