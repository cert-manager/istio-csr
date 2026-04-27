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
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2/ktesting"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	tlsfake "github.com/cert-manager/istio-csr/pkg/tls/fake"
)

func Test_Reconcile(t *testing.T) {
	const rootCAData = "root-ca"
	namespaceLabels := labels.Set{
		"istio-csr-injection": "enabled",
	}
	namespaceSelector := labels.SelectorFromSet(namespaceLabels)

	tests := map[string]struct {
		existingObjects []runtime.Object
		expResult       ctrl.Result
		expError        bool
		expObjects      []runtime.Object
	}{
		"if namespace doesn't exist, ignore": {
			existingObjects: nil,
			expResult:       ctrl.Result{},
			expError:        false,
			expObjects:      nil,
		},
		"if namespace is in a terminating state, ignore": {
			existingObjects: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: namespaceLabels},
					Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
				},
			},
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: namespaceLabels},
					Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
				},
			},
		},
		"if namespace exists, but configmap doesn't, create config map": {
			existingObjects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: namespaceLabels}},
			},
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: namespaceLabels}},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "istio-ca-root-cert", Namespace: "test-ns", ResourceVersion: "1", Labels: map[string]string{"istio.io/config": "true"}},
					Data:       map[string]string{"root-cert.pem": rootCAData},
				},
			},
		},
		"if namespace and configmap exists, but doesn't have any data, update with data": {
			existingObjects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: namespaceLabels}},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "istio-ca-root-cert", Namespace: "test-ns", ResourceVersion: "10", Labels: map[string]string{"istio.io/config": "true"}},
					Data:       nil,
				},
			},
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: namespaceLabels}},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "istio-ca-root-cert", Namespace: "test-ns", ResourceVersion: "11", Labels: map[string]string{"istio.io/config": "true"}},
					Data:       map[string]string{"root-cert.pem": rootCAData},
				},
			},
		},
		"if namespace and configmap exists, but doesn't have the right data, update with data": {
			existingObjects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: namespaceLabels}},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "istio-ca-root-cert", Namespace: "test-ns", ResourceVersion: "10", Labels: map[string]string{"istio.io/config": "true"}},
					Data:       map[string]string{"root-cert.pem": "not-root-ca"},
				},
			},
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: namespaceLabels}},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "istio-ca-root-cert", Namespace: "test-ns", ResourceVersion: "11", Labels: map[string]string{"istio.io/config": "true"}},
					Data:       map[string]string{"root-cert.pem": rootCAData},
				},
			},
		},
		"if namespace and configmap exists with correct data but with extra keys, remove extra keys": {
			existingObjects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: namespaceLabels}},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "istio-ca-root-cert", Namespace: "test-ns", ResourceVersion: "10", Labels: map[string]string{"istio.io/config": "true"}},
					Data:       map[string]string{"root-cert.pem": rootCAData, "foo": "bar"},
				},
			},
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: namespaceLabels}},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "istio-ca-root-cert", Namespace: "test-ns", ResourceVersion: "11", Labels: map[string]string{"istio.io/config": "true"}},
					Data:       map[string]string{"root-cert.pem": rootCAData},
				},
			},
		},
		"if namespace and configmap exists with correct data but wrong label, update with correct label": {
			existingObjects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: namespaceLabels}},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "istio-ca-root-cert", Namespace: "test-ns", ResourceVersion: "10", Labels: map[string]string{"istio.io/config": "false"}},
					Data:       map[string]string{"root-cert.pem": rootCAData, "foo": "bar"},
				},
			},
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: namespaceLabels}},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "istio-ca-root-cert", Namespace: "test-ns", ResourceVersion: "11", Labels: map[string]string{"istio.io/config": "true"}},
					Data:       map[string]string{"root-cert.pem": rootCAData},
				},
			},
		},
		"if namespace and configmap exists with correct data, do nothing": {
			existingObjects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: namespaceLabels}},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "istio-ca-root-cert", Namespace: "test-ns", ResourceVersion: "10", Labels: map[string]string{"istio.io/config": "true"}},
					Data:       map[string]string{"root-cert.pem": rootCAData},
				},
			},
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: namespaceLabels}},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "istio-ca-root-cert", Namespace: "test-ns", ResourceVersion: "10", Labels: map[string]string{"istio.io/config": "true"}},
					Data:       map[string]string{"root-cert.pem": rootCAData},
				},
			},
		},
		"if namespace and configmap exists with correct data and extra labels, do nothing": {
			existingObjects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: namespaceLabels}},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "istio-ca-root-cert", Namespace: "test-ns", ResourceVersion: "10", Labels: map[string]string{"istio.io/config": "true", "foo": "bar"}},
					Data:       map[string]string{"root-cert.pem": rootCAData},
				},
			},
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: namespaceLabels}},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "istio-ca-root-cert", Namespace: "test-ns", ResourceVersion: "10", Labels: map[string]string{"istio.io/config": "true", "foo": "bar"}},
					Data:       map[string]string{"root-cert.pem": rootCAData},
				},
			},
		},
		"if the namespace does not match the selector, do nothing": {
			existingObjects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: map[string]string{}}},
			},
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: []runtime.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", ResourceVersion: "10", Labels: map[string]string{}}},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fakeclient := fakeclient.NewClientBuilder().
				WithScheme(scheme.Scheme).
				WithRuntimeObjects(test.existingObjects...).
				Build()

			c := &configmap{
				client:            fakeclient,
				lister:            fakeclient,
				log:               ktesting.NewLogger(t, ktesting.DefaultConfig),
				tls:               tlsfake.New().WithRootCAs([]byte(rootCAData), nil),
				namespaceSelector: namespaceSelector,
				rootCAsPEM:        rootCAData,
			}

			result, err := c.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "test-ns", Name: "istio-ca-root-cert"}})
			assert.Equalf(t, test.expError, err != nil, "%v", err)
			assert.Equal(t, test.expResult, result)

			for _, expectedObject := range test.expObjects {
				expObj := expectedObject.(client.Object)
				var actual client.Object
				switch expObj.(type) {
				case *corev1.ConfigMap:
					actual = &corev1.ConfigMap{}
				case *corev1.Namespace:
					actual = &corev1.Namespace{}
				default:
					t.Errorf("unexpected object kind in expected: %#+v", expObj)
				}

				err := fakeclient.Get(t.Context(), client.ObjectKeyFromObject(expObj), actual)
				if err != nil {
					t.Errorf("unexpected error getting expected object: %s", err)
				} else if !apiequality.Semantic.DeepEqual(expObj, actual) {
					t.Errorf("unexpected expected object, exp=%#+v got=%#+v", expObj, actual)
				}
			}
		})
	}
}
