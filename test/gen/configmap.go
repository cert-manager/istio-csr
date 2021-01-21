package gen

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ConfigMapModifier func(*corev1.ConfigMap)

func ConfigMap(name string, mods ...ConfigMapModifier) *corev1.ConfigMap {
	c := &corev1.ConfigMap{
		ObjectMeta: ObjectMeta(name),
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func ConfigMapFrom(cm *corev1.ConfigMap, mods ...ConfigMapModifier) *corev1.ConfigMap {
	cm = cm.DeepCopy()
	for _, mod := range mods {
		mod(cm)
	}
	return cm
}

func SetConfigMapNamespace(ns string) ConfigMapModifier {
	return func(cm *corev1.ConfigMap) {
		cm.Namespace = ns
	}
}

func SetConfigMapData(data map[string]string) ConfigMapModifier {
	return func(cm *corev1.ConfigMap) {
		cm.Data = data
	}
}

func SetConfigMapResourceVersion(version string) ConfigMapModifier {
	return func(cm *corev1.ConfigMap) {
		cm.ResourceVersion = version
	}
}

func SetConfigMapLabels(labels map[string]string) ConfigMapModifier {
	return func(cm *corev1.ConfigMap) {
		cm.Labels = labels
	}
}
