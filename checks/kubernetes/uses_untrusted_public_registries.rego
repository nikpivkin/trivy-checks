# METADATA
# title: "Container images from public registries used"
# description: "Container images must not start with an empty prefix or a defined public registry domain."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# custom:
#   id: KSV-0034
#   aliases:
#     - AVD-KSV-0034
#     - KSV034
#     - no-public-registries
#   long_id: kubernetes-no-public-registries
#   severity: MEDIUM
#   recommended_action: "Use images from private registries."
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
package builtin.kubernetes.KSV034

import rego.v1

import data.lib.kubernetes

default failPublicRegistry := false

# list of untrusted public registries
untrusted_public_registries := [
	"docker.io",
	"ghcr.io",
]

# getContainersWithPublicRegistries returns a list of containers
# with public registry prefixes
getContainersWithPublicRegistries contains container if {
	container := kubernetes.containers[_]
	image := container.image
	untrusted := untrusted_public_registries[_]
	startswith(image, untrusted)
}

# getContainersWithPublicRegistries returns a list of containers
# with image without registry prefix
getContainersWithPublicRegistries contains container if {
	container := kubernetes.containers[_]
	image := container.image
	image_parts := split(image, "/") # get image registry/repo parts
	count(image_parts) > 0
	not contains(image_parts[0], ".") # check if first part is a url (assuming we have "." in url)
}

deny contains res if {
	container := getContainersWithPublicRegistries[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should restrict container image to use private registries", [container.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, container)
}
