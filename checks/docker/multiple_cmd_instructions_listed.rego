# METADATA
# title: "Multiple CMD instructions listed"
# description: "There can only be one CMD instruction in a Dockerfile. If you list more than one CMD then only the last CMD will take effect."
# scope: package
# schemas:
#   - input: schema["dockerfile"]
# related_resources:
#   - https://docs.docker.com/engine/reference/builder/#cmd
# custom:
#   id: DS-0016
#   aliases:
#     - AVD-DS-0016
#     - DS016
#     - only-one-cmd
#   long_id: docker-only-one-cmd
#   severity: HIGH
#   recommended_action: "Dockerfile should only have one CMD instruction. Remove all the other CMD instructions"
#   input:
#     selector:
#       - type: dockerfile
#   examples: checks/docker/multiple_cmd_instructions_listed.yaml
package builtin.dockerfile.DS016

import rego.v1

import data.lib.docker

deny contains res if {
	cmds := docker.stage_cmd[name]
	cnt := count(cmds)
	cnt > 1
	msg := sprintf("There are %d duplicate CMD instructions", [cnt])
	res := result.new(msg, cmds[1])
}
