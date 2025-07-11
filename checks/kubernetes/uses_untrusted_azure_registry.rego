# METADATA
# title: "All container images must start with the *.azurecr.io domain"
# description: "Containers should only use images from trusted registries."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# custom:
#   id: KSV-0032
#   aliases:
#     - AVD-KSV-0032
#     - KSV032
#     - use-azure-image-prefix
#   long_id: kubernetes-use-azure-image-prefix
#   severity: MEDIUM
#   recommended_action: "Use images from trusted Azure registries."
#   deprecated: true
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: pod
#           - kind: replicaset
#           - kind: replicationcontroller
#           - kind: deployment
#           - kind: deploymentconfig
#           - kind: statefulset
#           - kind: daemonset
#           - kind: cronjob
#           - kind: job
package builtin.kubernetes.KSV032

import rego.v1

import data.lib.kubernetes

default failTrustedAzureRegistry := false

# getContainersWithTrustedAzureRegistry returns a list of containers
# with image from a trusted Azure registry
getContainersWithTrustedAzureRegistry contains name if {
	container := kubernetes.containers[_]
	image := container.image

	# get image registry/repo parts
	image_parts := split(image, "/")

	# images with only one part do not specify a registry
	count(image_parts) > 1
	registry = image_parts[0]
	endswith(registry, "azurecr.io")
	name := container.name
}

# getContainersWithUntrustedAzureRegistry returns a list of containers
# with image from an untrusted Azure registry
getContainersWithUntrustedAzureRegistry contains container if {
	container := kubernetes.containers[_]
	not getContainersWithTrustedAzureRegistry[container.name]
}

deny contains res if {
	container := getContainersWithUntrustedAzureRegistry[_]
	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should restrict container image to your specific registry domain. For Azure any domain ending in 'azurecr.io'", [container.name, lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, container)
}
