package gen

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// DefaultTestNamespace is the default namespace set on resources that
	// are namespaced.
	DefaultTestNamespace = "default-unit-test-ns"
)

// ObjectMetaModifier applies a transformation to the provider ObjectMeta
type ObjectMetaModifier func(*metav1.ObjectMeta)

// ObjectMeta creates a new metav1.ObjectMeta with the given name, optionally
// applying the provided ObjectMetaModifiers.
// It applies a DefaultTestNamespace by default.
// Cluster-scoped resource generators should explicitly add `SetNamespace("")`
// to their constructors.
func ObjectMeta(name string, mods ...ObjectMetaModifier) metav1.ObjectMeta {
	m := &metav1.ObjectMeta{
		Name:      name,
		Namespace: DefaultTestNamespace,
		Labels:    make(map[string]string),
	}
	for _, mod := range mods {
		mod(m)
	}
	return *m
}
