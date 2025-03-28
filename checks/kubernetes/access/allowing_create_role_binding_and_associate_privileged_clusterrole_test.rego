package builtin.kubernetes.KSV051

import rego.v1

test_allowing_create_role_binding_and_associate_clusterrole if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["rolebindings"],
				"verbs": ["create"],
			},
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["clusterroles"],
				"verbs": ["bind"],
				"resourceNames": ["*"],
			},
		],
	}

	count(r) == 1
}

test_allowing_create_role_binding_and_associate_clusterrole_resource_not_role_binding if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["rolebindings1"],
				"verbs": ["create"],
			},
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["clusterroles"],
				"verbs": ["bind"],
				"resourceNames": ["*"],
			},
		],
	}

	count(r) == 0
}

test_allowing_create_role_binding_and_associate_clusterrole_verb_not_create if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["rolebindings"],
				"verbs": ["create1"],
			},
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["clusterroles"],
				"verbs": ["bind"],
				"resourceNames": ["*"],
			},
		],
	}

	count(r) == 0
}

test_allowing_create_role_binding_and_associate_clusterrole_resource_not_role if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["rolebindings"],
				"verbs": ["create1"],
			},
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["roles1"],
				"verbs": ["bind"],
				"resourceNames": ["*"],
			},
		],
	}

	count(r) == 0
}

test_allowing_create_role_binding_and_associate_clusterrole_verb_not_bind if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["rolebindings"],
				"verbs": ["create1"],
			},
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["clusterroles"],
				"verbs": ["bind1"],
				"resourceNames": ["*"],
			},
		],
	}

	count(r) == 0
}

test_allowing_create_role_binding_and_associate_clusterrole_resourceNames_not_any if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["rolebindings"],
				"verbs": ["create1"],
			},
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["clusterroles"],
				"verbs": ["bind1"],
				"resourceNames": ["aa"],
			},
		],
	}

	count(r) == 0
}

test_allowing_create_role_binding_and_associate_role if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["rolebindings"],
				"verbs": ["create"],
			},
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["roles"],
				"verbs": ["bind"],
				"resourceNames": ["*"],
			},
		],
	}

	count(r) > 0
}

test_allowing_create_role_binding_and_associate_role_resource_not_role_binding if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["rolebindings1"],
				"verbs": ["create"],
			},
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["roles"],
				"verbs": ["bind"],
				"resourceNames": ["*"],
			},
		],
	}

	count(r) == 0
}

test_allowing_create_role_binding_and_associate_role_verb_not_create if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["rolebindings"],
				"verbs": ["create1"],
			},
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["roles"],
				"verbs": ["bind"],
				"resourceNames": ["*"],
			},
		],
	}

	count(r) == 0
}

test_allowing_create_role_binding_and_associate_role_resource_not_role if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["rolebindings"],
				"verbs": ["create1"],
			},
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["roles1"],
				"verbs": ["bind"],
				"resourceNames": ["*"],
			},
		],
	}

	count(r) == 0
}

test_allowing_create_role_binding_and_associate_role_verb_not_bind if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["rolebindings"],
				"verbs": ["create1"],
			},
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["roles"],
				"verbs": ["bind1"],
				"resourceNames": ["*"],
			},
		],
	}

	count(r) == 0
}

test_allowing_create_role_binding_and_associate_role_resourceNames_not_any if {
	r := deny with input as {
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind": "Role",
		"metadata": {
			"namespace": "default",
			"name": "pod-reader",
		},
		"rules": [
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["rolebindings"],
				"verbs": ["create1"],
			},
			{
				"apiGroups": ["rbac.authorization.k8s.io"],
				"resources": ["roles"],
				"verbs": ["bind1"],
				"resourceNames": ["aa"],
			},
		],
	}

	count(r) == 0
}
