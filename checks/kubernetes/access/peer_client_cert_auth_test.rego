package builtin.kubernetes.KCV0046

import rego.v1

test_peer_client_cert_auth_is_set_to_true if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "etcd",
			"labels": {
				"component": "etcd",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["etcd", "--advertise-client-urls=https://192.168.49.2:2379", "--peer-client-cert-auth=true"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_peer_client_cert_auth_is_set_to_true_args if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "etcd",
			"labels": {
				"component": "etcd",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["--advertise-client-urls=https://192.168.49.2:2379", "--peer-client-cert-auth=true"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_peer_client_cert_auth_is_set_to_false if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "etcd",
			"labels": {
				"component": "etcd",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["etcd", "--advertise-client-urls=https://192.168.49.2:2379", "--peer-client-cert-auth=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --peer-client-cert-auth argument is set to true"
}

test_peer_client_cert_auth_is_not_configured if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "etcd",
			"labels": {
				"component": "etcd",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["etcd", "--advertise-client-urls=https://192.168.49.2:2379"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --peer-client-cert-auth argument is set to true"
}
