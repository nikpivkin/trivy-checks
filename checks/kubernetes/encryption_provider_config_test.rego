package builtin.kubernetes.KCV0030

import rego.v1

test_encryption_provider_config_is_set if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "apiserver",
			"labels": {
				"component": "kube-apiserver",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-apiserver", "--advertise-address=192.168.49.2", "--encryption-provider-config=<filename>"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_encryption_provider_config_is_not_set if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "apiserver",
			"labels": {
				"component": "kube-apiserver",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-apiserver", "--advertise-address=192.168.49.2", "--anonymous-auth=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --encryption-provider-config argument is set as appropriate"
}

test_encryption_provider_config_is_set_args if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "apiserver",
			"labels": {
				"component": "kube-apiserver",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-apiserver"],
			"args": ["--advertise-address=192.168.49.2", "--encryption-provider-config=<filename>"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_encryption_provider_config_is_not_set_args if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "apiserver",
			"labels": {
				"component": "kube-apiserver",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-apiserver"],
			"args": ["--advertise-address=192.168.49.2", "--anonymous-auth=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --encryption-provider-config argument is set as appropriate"
}
