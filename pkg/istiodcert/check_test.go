/*
Copyright 2026 The cert-manager Authors.

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

package istiodcert

import (
	"net/http/httptest"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmfake "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestCheck(t *testing.T) {
	certWithReady := func(status cmmeta.ConditionStatus) *cmapi.Certificate {
		return &cmapi.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: "istiod", Namespace: "istio-system"},
			Status: cmapi.CertificateStatus{Conditions: []cmapi.CertificateCondition{
				{Type: cmapi.CertificateConditionReady, Status: status},
			}},
		}
	}

	tests := map[string]struct {
		objects []runtime.Object
		wantErr string
	}{
		"certificate not created yet": {
			wantErr: "failed to get istiod certificate istio-system/istiod",
		},
		"certificate not ready": {
			objects: []runtime.Object{certWithReady(cmmeta.ConditionFalse)},
			wantErr: "istiod certificate istio-system/istiod is not ready yet",
		},
		"certificate without conditions": {
			objects: []runtime.Object{&cmapi.Certificate{ObjectMeta: metav1.ObjectMeta{Name: "istiod", Namespace: "istio-system"}}},
			wantErr: "istiod certificate istio-system/istiod is not ready yet",
		},
		"certificate ready": {
			objects: []runtime.Object{certWithReady(cmmeta.ConditionTrue)},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := cmfake.NewClientset(test.objects...)
			dicp := &DynamicIstiodCertProvisioner{
				certManagerClient: client.CertmanagerV1().Certificates("istio-system"),
				opts:              Options{CertificateName: "istiod", CertificateNamespace: "istio-system"},
			}

			err := dicp.Check(httptest.NewRequest("GET", "/readyz", nil))
			if test.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, test.wantErr)
		})
	}
}
