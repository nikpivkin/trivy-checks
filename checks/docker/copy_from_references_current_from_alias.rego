# METADATA
# title: "COPY '--from' referring to the current image"
# description: "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself."
# scope: package
# schemas:
#   - input: schema["dockerfile"]
# related_resources:
#   - https://docs.docker.com/develop/develop-images/multistage-build/
# custom:
#   id: DS-0006
#   aliases:
#     - AVD-DS-0006
#     - DS006
#     - no-self-referencing-copy-from
#   long_id: docker-no-self-referencing-copy-from
#   severity: CRITICAL
#   recommended_action: "Change the '--from' so that it will not refer to itself"
#   input:
#     selector:
#       - type: dockerfile
#   examples: checks/docker/copy_from_references_current_from_alias.yaml
package builtin.dockerfile.DS006

import rego.v1

import data.lib.docker

get_alias_from_copy contains output if {
	copies := docker.stage_copies[stage]

	copy := copies[_]
	flag := copy.Flags[_]
	contains(flag, "--from=")
	parts := split(flag, "=")

	is_alias_current_from_alias(stage.Name, parts[1])
	args := parts[1]
	output := {
		"args": args,
		"cmd": copy,
	}
}

is_alias_current_from_alias(current_name, current_alias) := allow if {
	current_name_lower := lower(current_name)
	current_alias_lower := lower(current_alias)

	#expecting stage name as "myimage:tag as dep"
	[_, alias] := regex.split(`\s+as\s+`, current_name_lower)

	alias == current_alias_lower

	allow = true
}

deny contains res if {
	output := get_alias_from_copy[_]
	msg := sprintf("'COPY --from' should not mention current alias '%s' since it is impossible to copy from itself", [output.args])
	res := result.new(msg, output.cmd)
}
