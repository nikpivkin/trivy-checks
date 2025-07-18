# METADATA
# title: "Tiller Is Deployed"
# description: "Check if Helm Tiller component is deployed."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# custom:
#   id: KSV-0102
#   aliases:
#     - AVD-KSV-0102
#     - KSV102
#     - no-tiller
#   long_id: kubernetes-no-tiller
#   severity: CRITICAL
#   recommended_action: "Migrate to Helm v3 which no longer has Tiller component"
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KSV102

import rego.v1

import data.lib.kubernetes

# Get all containers and check kubernetes metadata for tiller
tillerDeployed contains container if {
	container := kubernetes.containers[_]
	checkMetadata(input.metadata)
}

# Get all containers and check each image for tiller
tillerDeployed contains container if {
	container := kubernetes.containers[_]
	contains(container.image, "tiller")
}

# Get all pods and check each metadata for tiller
tillerDeployed contains pod if {
	pod := kubernetes.pods[_]
	checkMetadata(pod.metadata)
}

getName(output) := name if {
	name := output.metadata.name
}

getName(output) := name if {
	name := output.name
}

# Check for tiller by resource name
checkMetadata(metadata) if {
	contains(metadata.name, "tiller")
}

# Check for tiller by app label
checkMetadata(metadata) if {
	metadata.labels.app == "helm"
}

# Check for tiller by name label
checkMetadata(metadata) if {
	metadata.labels.name == "tiller"
}

deny contains res if {
	output := tillerDeployed[_]
	msg := kubernetes.format(sprintf("container '%s' of %s '%s' in '%s' namespace shouldn't have tiller deployed", [getName(output), lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, output)
}
