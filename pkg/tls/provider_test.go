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

func TestNewProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                  string
		opts                  Options
		wantSuccess           bool
		wantErr               string
		applyCipherSuites     bool
		applyCurvePreferences bool
	}{
		{
			name:        "empty options use Go TLS defaults",
			opts:        Options{},
			wantSuccess: true,
		},
		{
			name: "explicit cipher suites",
			opts: Options{
				ServingTLSCipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			},
			wantSuccess:       true,
			applyCipherSuites: true,
		},
		{
			name: "explicit curve preferences",
			opts: Options{
				ServingTLSCurvePreferences: []string{"X25519"},
			},
			wantSuccess:           true,
			applyCurvePreferences: true,
		},
		{
			name: "invalid cipher suite",
			opts: Options{
				ServingTLSCipherSuites: []string{"NOT_A_CIPHER_SUITE"},
			},
		},
		{
			name: "invalid min TLS version name",
			opts: Options{
				ServingTLSMinVersion: "VersionTLS0xBAD",
			},
		},
		{
			name: "min TLS version below 1.2",
			opts: Options{
				ServingTLSMinVersion: "VersionTLS11",
			},
			wantErr: "serving tls min version must be VersionTLS12 or higher",
		},
		{
			name: "invalid curve preference",
			opts: Options{
				ServingTLSCurvePreferences: []string{"not-a-curve"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewProvider(logr.Discard(), cmfake.New(), tt.opts, stubIssuerNotifier{})
			if !tt.wantSuccess {
				if tt.wantErr != "" {
					require.EqualError(t, err, tt.wantErr)
					return
				}
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, p)
			require.Equal(t, tt.applyCipherSuites, p.servingApplyCipherSuites)
			require.Equal(t, tt.applyCurvePreferences, p.servingApplyCurvePrefs)
		})
	}
}
