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

package tls

import (
	"context"
	"testing"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	"github.com/cert-manager/istio-csr/pkg/certmanager"
	cmfake "github.com/cert-manager/istio-csr/pkg/certmanager/fake"
)

type stubIssuerNotifier struct{}

func (stubIssuerNotifier) WaitForIssuerConfig(context.Context) {}

func (stubIssuerNotifier) SubscribeIssuerChange() *certmanager.IssuerChangeSubscription {
	return nil
}

func (stubIssuerNotifier) HasIssuerConfig() bool { return true }

func (stubIssuerNotifier) InitialIssuer() *cmmeta.IssuerReference { return nil }

func TestNewProvider_InvalidServingTLS(t *testing.T) {
	t.Parallel()
	_, err := NewProvider(logr.Discard(), cmfake.New(), Options{
		ServingTLSCipherSuites: []string{"NOT_A_CIPHER_SUITE"},
	}, stubIssuerNotifier{})
	require.Error(t, err)

	_, err = NewProvider(logr.Discard(), cmfake.New(), Options{
		ServingTLSMinVersion: "VersionTLS0xBAD",
	}, stubIssuerNotifier{})
	require.Error(t, err)

	_, err = NewProvider(logr.Discard(), cmfake.New(), Options{
		ServingTLSMinVersion: "VersionTLS11",
	}, stubIssuerNotifier{})
	require.EqualError(t, err, "serving tls min version must be VersionTLS12 or higher")
}

func TestNewProvider_ValidServingTLSDefaults(t *testing.T) {
	t.Parallel()
	p, err := NewProvider(logr.Discard(), cmfake.New(), Options{}, stubIssuerNotifier{})
	require.NoError(t, err)
	require.NotNil(t, p)
	require.False(t, p.servingApplyCipherSuites)
	require.False(t, p.servingApplyCurvePrefs)
}
