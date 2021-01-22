package controller

import (
	"context"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2/klogr"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/cert-manager/istio-csr/test/gen"
)

func TestConfigMap(t *testing.T) {
	var (
		testNamespacedName = types.NamespacedName{
			Namespace: "test-ns",
			Name:      "test-name",
		}

		baseConfigMap = gen.ConfigMap(testNamespacedName.Name,
			gen.SetConfigMapNamespace(testNamespacedName.Namespace),
		)
	)

	tests := map[string]struct {
		objects      []runtime.Object
		expConfigMap *corev1.ConfigMap
	}{
		"if ConfigMap doesn't exist, should create a new one, with data set": {
			objects: []runtime.Object{},
			expConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("1"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"foo": "bar",
				}),
			),
		},
		"if ConfigMap exists, but doesn't include any data, should update with the correct data": {
			objects: []runtime.Object{
				gen.ConfigMapFrom(baseConfigMap,
					gen.SetConfigMapResourceVersion("1"),
					gen.SetConfigMapLabels(map[string]string{
						IstioConfigLabelKey: "true",
					}),
					gen.SetConfigMapData(nil),
				),
			},
			expConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("2"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"foo": "bar",
				}),
			),
		},
		"if ConfigMap exists, but doesn't have any labels, should update with the correct label": {
			objects: []runtime.Object{
				gen.ConfigMapFrom(baseConfigMap,
					gen.SetConfigMapResourceVersion("1"),
					gen.SetConfigMapLabels(nil),
					gen.SetConfigMapData(nil),
				),
			},
			expConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("2"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"foo": "bar",
				}),
			),
		},
		"if ConfigMap exists, but the data value is wrong, should update with the correct data": {
			objects: []runtime.Object{
				gen.ConfigMapFrom(baseConfigMap,
					gen.SetConfigMapResourceVersion("1"),
					gen.SetConfigMapLabels(map[string]string{
						IstioConfigLabelKey: "true",
					}),
					gen.SetConfigMapData(map[string]string{
						"foo": "foo",
					}),
				),
			},
			expConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("2"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"foo": "bar",
				}),
			),
		},
		"if ConfigMap exists, but with extra data keys, should preserve those keys": {
			objects: []runtime.Object{
				gen.ConfigMapFrom(baseConfigMap,
					gen.SetConfigMapResourceVersion("1"),
					gen.SetConfigMapLabels(map[string]string{
						IstioConfigLabelKey: "true",
					}),
					gen.SetConfigMapData(map[string]string{
						"bar": "bar",
						"123": "456",
					}),
				),
			},
			expConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("2"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"foo": "bar",
					"bar": "bar",
					"123": "456",
				}),
			),
		},
		"if ConfigMap exists, but with wrong label value, should overrite the value": {
			objects: []runtime.Object{
				gen.ConfigMapFrom(baseConfigMap,
					gen.SetConfigMapResourceVersion("1"),
					gen.SetConfigMapLabels(map[string]string{
						IstioConfigLabelKey: "false",
					}),
					gen.SetConfigMapData(map[string]string{
						"foo": "bar",
					}),
				),
			},
			expConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("2"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"foo": "bar",
				}),
			),
		},
		"if ConfigMap exists, but with extra label keys, should preserve those keys": {
			objects: []runtime.Object{
				gen.ConfigMapFrom(baseConfigMap,
					gen.SetConfigMapResourceVersion("1"),
					gen.SetConfigMapLabels(map[string]string{
						"foo-bar": "true",
					}),
					gen.SetConfigMapData(map[string]string{
						"foo": "bar",
					}),
				),
			},
			expConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("2"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
					"foo-bar":           "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"foo": "bar",
				}),
			),
		},
		"if ConfigMap exists with exact data, shouldn't update": {
			objects: []runtime.Object{
				gen.ConfigMapFrom(baseConfigMap,
					gen.SetConfigMapResourceVersion("1"),
					gen.SetConfigMapLabels(map[string]string{
						IstioConfigLabelKey: "true",
					}),
					gen.SetConfigMapData(map[string]string{
						"foo": "bar",
					}),
				),
			},
			expConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("1"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
				}),
				gen.SetConfigMapData(map[string]string{
					"foo": "bar",
				}),
			),
		},
		"if ConfigMap exists with extra data, shouldn't update": {
			objects: []runtime.Object{
				gen.ConfigMapFrom(baseConfigMap,
					gen.SetConfigMapResourceVersion("1"),
					gen.SetConfigMapLabels(map[string]string{
						IstioConfigLabelKey: "true",
						"foo":               "bar",
					}),
					gen.SetConfigMapData(map[string]string{
						"foo": "bar",
						"123": "456",
					}),
				),
			},
			expConfigMap: gen.ConfigMapFrom(baseConfigMap,
				gen.SetConfigMapResourceVersion("1"),
				gen.SetConfigMapLabels(map[string]string{
					IstioConfigLabelKey: "true",
					"foo":               "bar",
				}),
				gen.SetConfigMapData(map[string]string{
					"foo": "bar",
					"123": "456",
				}),
			),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := k8sscheme.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}

			fakeclient := fakeclient.NewClientBuilder().
				WithRuntimeObjects(test.objects...).
				WithScheme(scheme).
				Build()

			enforcer := &enforcer{
				client: fakeclient,
				data: map[string]string{
					"foo": "bar",
				},
				configMapName: testNamespacedName.Name,
			}

			err := enforcer.configmap(context.TODO(), klogr.New(), testNamespacedName.Namespace)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}

			cm := new(corev1.ConfigMap)
			err = fakeclient.Get(context.TODO(), testNamespacedName, cm)
			if err != nil {
				t.Errorf("unexpected error getting ConfigMap: %s", err)
			}

			if !reflect.DeepEqual(cm, test.expConfigMap) {
				t.Errorf("mismatch resulting ConfigMap  and expecting, exp=%#+v got=%#+v",
					test.expConfigMap, cm)
			}
		})
	}
}
