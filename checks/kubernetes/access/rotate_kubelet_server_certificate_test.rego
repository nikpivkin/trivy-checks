package builtin.kubernetes.KCV0038

import rego.v1

test_use_rotate_kubelet_server_certificate_is_set_to_true if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "controller-manager",
			"labels": {
				"component": "kube-controller-manager",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-controller-manager", "--feature-gates=RotateKubeletServerCertificate=true"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_use_rotate_kubelet_server_certificate_is_set_to_true_args if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "controller-manager",
			"labels": {
				"component": "kube-controller-manager",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-controller-manager"],
			"args": ["--feature-gates=RotateKubeletServerCertificate=true"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_use_rotate_kubelet_server_certificate_is_set_to_false if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "controller-manager",
			"labels": {
				"component": "kube-controller-manager",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-controller-manager", "--feature-gates=RotateKubeletServerCertificate=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the RotateKubeletServerCertificate argument is set to true"
}

test_use_rotate_kubelet_server_certificate_is_not_configured if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "controller-manager",
			"labels": {
				"component": "kube-controller-manager",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-controller-manager", "--allocate-node-cidrs=true", "--feature-gates=Test=true"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the RotateKubeletServerCertificate argument is set to true"
}
