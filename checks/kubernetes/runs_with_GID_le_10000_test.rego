package builtin.kubernetes.KSV021

import rego.v1

test_GID_gt_10000_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-gid"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"runAsGroup": 10004},
		}]},
	}

	count(r) == 0
}

test_no_run_as_group_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-gid"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-gid' should set 'securityContext.runAsGroup' > 10000"
}

test_low_gid_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-gid"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"runAsGroup": 100},
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-gid' should set 'securityContext.runAsGroup' > 10000"
}

test_pod_sec_ctx_low_gid_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-gid"},
		"spec": {
			"securityContext": {"runAsGroup": 100},
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
		},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-gid' should set 'securityContext.runAsGroup' > 10000"
}
