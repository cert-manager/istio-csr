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

package controller

import (
	"context"
	"crypto/x509"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2/klogr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/cert-manager/istio-csr/test/gen"
)

var (
	testNamespacedName = types.NamespacedName{
		Namespace: "test-ns",
		Name:      "test-name",
	}
	baseConfigMap = gen.ConfigMap(testNamespacedName.Name,
		gen.SetConfigMapNamespace(testNamespacedName.Namespace),
	)
)

type testCase struct {
	existingConfigMap *corev1.ConfigMap
	existingNamespace *corev1.Namespace
	expConfigMap      *corev1.ConfigMap
}

type suite map[string]*testCase

func (s suite) withNamespace(ns *corev1.Namespace) suite {
	for k := range s {
		s[k].existingNamespace = ns
	}
	return s
}

func TestConfigMapReconcile(t *testing.T) {
	for name, test := range buildSuite() {
		t.Run(name, func(t *testing.T) {
			client := buildClient(t, test)

			c := &configmap{
				log: klogr.New(),
				enforcer: &enforcer{
					client:        client,
					rootCAs:       func() ([]byte, *x509.CertPool) { return []byte("bar"), nil },
					configMapName: testNamespacedName.Name,
				},
			}

			result, err := c.Reconcile(context.TODO(), ctrl.Request{
				NamespacedName: testNamespacedName,
			})
			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}

			if !reflect.DeepEqual(result, ctrl.Result{}) {
				t.Errorf("unexpected result, exp=%v got=%v",
					ctrl.Result{}, result)
			}

			assertConfigMap(t, test, client)
		})
	}
}

func TestNamespaceReconcile(t *testing.T) {
	tests := make(map[string]*testCase)
	exists := buildSuite()

	for name, test := range exists {
		// Add existing Namespace
		test.existingNamespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNamespacedName.Namespace,
			},
			Status: corev1.NamespaceStatus{
				Phase: corev1.NamespaceActive,
			},
		}

		tests["[namespace exists] "+name] = test
	}

	notexists := buildSuite()
	for name, test := range notexists {
		test.existingNamespace = nil
		// Shouldn't change the configmap, so assert that it stays the same
		if test.existingConfigMap == nil {
			test.expConfigMap = new(corev1.ConfigMap)
		} else {
			test.expConfigMap = test.existingConfigMap
		}
		tests["[namespace not exists] "+name] = test
	}

	terminating := buildSuite()
	for name, test := range terminating {
		test.existingNamespace = nil
		// Add terminating Namespace
		test.existingNamespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNamespacedName.Namespace,
			},
			Status: corev1.NamespaceStatus{
				Phase: corev1.NamespaceTerminating,
			},
		}
		if test.existingConfigMap == nil {
			test.expConfigMap = new(corev1.ConfigMap)
		} else {
			test.expConfigMap = test.existingConfigMap
		}

		tests["[namespace terminating] "+name] = test
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := buildClient(t, test)

			ns := &namespace{
				log: klogr.New(),
				enforcer: &enforcer{
					client:        client,
					rootCAs:       func() ([]byte, *x509.CertPool) { return []byte("bar"), nil },
					configMapName: testNamespacedName.Name,
				},
			}

			result, err := ns.Reconcile(context.TODO(), ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name: testNamespacedName.Namespace,
				},
			})
			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}
			if !reflect.DeepEqual(result, ctrl.Result{}) {
				t.Errorf("unexpected result, exp=%v got=%v",
					ctrl.Result{}, result)
			}

			assertConfigMap(t, test, client)
		})
	}

}

func TestEnforcerConfigMap(t *testing.T) {
	for name, test := range buildSuite() {
		t.Run(name, func(t *testing.T) {
			client := buildClient(t, test)
			enforcer := &enforcer{
				client:        client,
				rootCAs:       func() ([]byte, *x509.CertPool) { return []byte("bar"), nil },
				configMapName: testNamespacedName.Name,
			}

			err := enforcer.configmap(context.TODO(), klogr.New(), testNamespacedName.Namespace)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}

			assertConfigMap(t, test, client)
		})
	}
}

func buildClient(t *testing.T, test *testCase) client.Client {
	scheme := runtime.NewScheme()
	if err := k8sscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	client := fakeclient.NewClientBuilder().WithScheme(scheme)

	var objects []runtime.Object
	if test.existingConfigMap != nil {
		objects = append(objects, test.existingConfigMap)
	}
	if test.existingNamespace != nil {
		objects = append(objects, test.existingNamespace)
	}
	if len(objects) > 0 {
		client = client.WithRuntimeObjects(objects...)
	}
	return client.Build()
}

func assertConfigMap(t *testing.T, test *testCase, client client.Client) {
	cm := new(corev1.ConfigMap)
	if err := client.Get(context.TODO(), testNamespacedName, cm); err != nil &&
		!reflect.DeepEqual(test.expConfigMap, new(corev1.ConfigMap)) {
		t.Errorf("unexpected error getting ConfigMap: %s", err)
	}

	if !reflect.DeepEqual(cm, test.expConfigMap) {
		t.Errorf("mismatch resulting ConfigMap  and expecting, exp=%#+v got=%#+v",
			test.expConfigMap, cm)
	}
}

// suite hold a suite of tests that should assert some behaviour, unless overridden.
func buildSuite() suite {
	return map[string]*testCase{
		"if ConfigMap doesn't exist, should create a new one, with data set": {
			existingConfigMap: nil,
			expConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("1"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"root-cert.pem": "bar",
				}),
			),
		},
		"if ConfigMap exists, but doesn't include any data, should update with the correct data": {
			existingConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("1"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
				}),
				gen.SetConfigMapData(nil),
			),
			expConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("2"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"root-cert.pem": "bar",
				}),
			),
		},
		"if ConfigMap exists, but doesn't have any labels, should update with the correct label": {
			existingConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("1"),
				gen.SetConfigMapLabels(nil),
				gen.SetConfigMapData(nil),
			),
			expConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("2"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"root-cert.pem": "bar",
				}),
			),
		},
		"if ConfigMap exists, but the data value is wrong, should update with the correct data": {
			existingConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("1"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"root-cert.pem": "foo",
				}),
			),
			expConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("2"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"root-cert.pem": "bar",
				}),
			),
		},
		"if ConfigMap exists, but with extra data keys, should preserve those keys": {
			existingConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("1"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"bar": "bar",
					"123": "456",
				}),
			),
			expConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("2"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"root-cert.pem": "bar",
					"bar":           "bar",
					"123":           "456",
				}),
			),
		},
		"if ConfigMap exists, but with wrong label value, should overrite the value": {
			existingConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("1"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "false",
				}),
				gen.SetConfigMapData(map[string]string{
					"root-cert.pem": "bar",
				}),
			),
			expConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("2"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"root-cert.pem": "bar",
				}),
			),
		},
		"if ConfigMap exists with exact data, shouldn't update": {
			existingConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("1"),
				gen.SetConfigMapLabels(map[string]string{
					"foo-bar": "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"root-cert.pem": "bar",
				}),
			),
			expConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("2"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
					"foo-bar":           "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"root-cert.pem": "bar",
				}),
			),
		},
		"if ConfigMap exists with extra data, shouldn't update": {
			existingConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("1"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
					"foo":               "bar",
				}),
				gen.SetConfigMapData(map[string]string{
					"root-cert.pem": "bar",
					"123":           "456",
				}),
			),
			expConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("1"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
					"foo":               "bar",
				}),
				gen.SetConfigMapData(map[string]string{
					"root-cert.pem": "bar",
					"123":           "456",
				}),
			),
		},
	}
}
