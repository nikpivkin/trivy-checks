# METADATA
# title: "All container images must start with an ECR domain"
# description: "Container images from non-ECR registries should be forbidden."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# custom:
#   id: KSV-0035
#   aliases:
#     - AVD-KSV-0035
#     - KSV035
#     - no-untrusted-ecr-domain
#   long_id: kubernetes-no-untrusted-ecr-domain
#   severity: MEDIUM
#   recommended_action: "Container image should be used from Amazon container Registry"
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
package builtin.kubernetes.KSV035

import rego.v1

import data.lib.kubernetes

default failTrustedECRRegistry := false

# list of trusted ECR registries
trusted_ecr_registries := [
	"ecr.us-east-2.amazonaws.com",
	"ecr.us-east-1.amazonaws.com",
	"ecr.us-west-1.amazonaws.com",
	"ecr.us-west-2.amazonaws.com",
	"ecr.af-south-1.amazonaws.com",
	"ecr.ap-east-1.amazonaws.com",
	"ecr.ap-south-1.amazonaws.com",
	"ecr.ap-northeast-2.amazonaws.com",
	"ecr.ap-southeast-1.amazonaws.com",
	"ecr.ap-southeast-2.amazonaws.com",
	"ecr.ap-northeast-1.amazonaws.com",
	"ecr.ca-central-1.amazonaws.com",
	"ecr.cn-north-1.amazonaws.com.cn",
	"ecr.cn-northwest-1.amazonaws.com.cn",
	"ecr.eu-central-1.amazonaws.com",
	"ecr.eu-west-1.amazonaws.com",
	"ecr.eu-west-2.amazonaws.com",
	"ecr.eu-south-1.amazonaws.com",
	"ecr.eu-west-3.amazonaws.com",
	"ecr.eu-north-1.amazonaws.com",
	"ecr.me-south-1.amazonaws.com",
	"ecr.sa-east-1.amazonaws.com",
	"ecr.us-gov-east-1.amazonaws.com",
	"ecr.us-gov-west-1.amazonaws.com",
]

# getContainersWithTrustedECRRegistry returns a list of containers
# with image from a trusted ECR registry
getContainersWithTrustedECRRegistry contains name if {
	container := kubernetes.containers[_]
	image := container.image

	# get image registry/repo parts
	image_parts := split(image, "/")

	# images with only one part do not specify a registry
	count(image_parts) > 1
	registry = image_parts[0]
	trusted := trusted_ecr_registries[_]
	endswith(registry, trusted)
	name := container.name
}

# getContainersWithUntrustedECRRegistry returns a list of containers
# with image from an untrusted ECR registry
getContainersWithUntrustedECRRegistry contains container if {
	container := kubernetes.containers[_]
	not getContainersWithTrustedECRRegistry[container.name]
}

deny contains res if {
	container := getContainersWithUntrustedECRRegistry[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should restrict images to own ECR repository. See the full ECR list here: https://docs.aws.amazon.com/general/latest/gr/ecr.html", [container.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, container)
}
