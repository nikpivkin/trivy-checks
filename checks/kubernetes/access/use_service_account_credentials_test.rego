package builtin.kubernetes.KCV0035

import rego.v1

test_use_service_account_credentials_is_set_to_true if {
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
			"command": ["kube-controller-manager", "--allocate-node-cidrs=true", "--use-service-account-credentials=true"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_use_service_account_credentials_is_set_to_true_args if {
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
			"args": ["--allocate-node-cidrs=true", "--use-service-account-credentials=true"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_use_service_account_credentials_is_set_to_false if {
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
			"command": ["kube-controller-manager", "--allocate-node-cidrs=true", "--use-service-account-credentials=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --use-service-account-credentials argument is set to true"
}

test_use_service_account_credentials_is_not_configured if {
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
			"command": ["kube-controller-manager", "--allocate-node-cidrs=true"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --use-service-account-credentials argument is set to true"
}
