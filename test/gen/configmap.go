/*
Copyright 2021 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
