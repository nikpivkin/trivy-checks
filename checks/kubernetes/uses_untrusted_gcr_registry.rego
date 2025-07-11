# METADATA
# title: "All container images must start with a GCR domain"
# description: "Containers should only use images from trusted GCR registries."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# custom:
#   id: KSV-0033
#   aliases:
#     - AVD-KSV-0033
#     - KSV033
#     - use-gcr-domain
#   long_id: kubernetes-use-gcr-domain
#   severity: MEDIUM
#   recommended_action: "Use images from trusted GCR registries."
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
package builtin.kubernetes.KSV033

import rego.v1

import data.lib.kubernetes

default failTrustedGCRRegistry := false

# list of trusted GCR registries
trusted_gcr_registries := [
	"gcr.io",
	"us.gcr.io",
	"eu.gcr.io",
	"asia.gcr.io",
]

# getContainersWithTrustedGCRRegistry returns a list of containers
# with image from a trusted gcr registry
getContainersWithTrustedGCRRegistry contains name if {
	container := kubernetes.containers[_]
	image := container.image

	# get image registry/repo parts
	image_parts := split(image, "/")

	# images with only one part do not specify a registry
	count(image_parts) > 1
	registry = image_parts[0]
	trusted := trusted_gcr_registries[_]
	endswith(registry, trusted)
	name := container.name
}

# getContainersWithUntrustedGCRRegistry returns a list of containers
# with image from an untrusted gcr registry
getContainersWithUntrustedGCRRegistry contains container if {
	container := kubernetes.containers[_]
	not getContainersWithTrustedGCRRegistry[container.name]
}

deny contains res if {
	container := getContainersWithUntrustedGCRRegistry[_]
	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should restrict container image to your specific registry domain. See the full GCR list here: https://cloud.google.com/container-registry/docs/overview#registries", [container.name, lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, container)
}
