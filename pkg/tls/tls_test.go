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
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	cliflag "k8s.io/component-base/cli/flag"

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

func mustTestCA(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	caKey, err := pki.GenerateECPrivateKey(256)
	require.NoError(t, err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    x509.ECDSA,
		PublicKey:             caKey.Public(),
		IsCA:                  true,
		Subject: pkix.Name{
			CommonName: "test-ca",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	_, caCert, err := pki.SignCertificate(template, template, caKey.Public(), caKey)
	require.NoError(t, err)

	return caCert, caKey
}

func testSigner(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer) certmanager.Signer {
	t.Helper()

	return cmfake.New().WithSign(func(_ context.Context, _ string, csrPEM []byte, duration time.Duration, _ []cmapi.KeyUsage) (certmanager.Bundle, error) {
		template, err := pki.CertificateTemplateFromCSRPEM(csrPEM)
		if err != nil {
			return certmanager.Bundle{}, err
		}
		template.NotAfter = time.Now().Add(duration)

		pemBundle, err := pki.SignCSRTemplate([]*x509.Certificate{caCert}, caKey, template)
		if err != nil {
			return certmanager.Bundle{}, err
		}

		return certmanager.Bundle{
			Certificate: pemBundle.ChainPEM,
			CA:          pemBundle.CAPEM,
		}, nil
	})
}

func assertServingTLSConfig(
	t *testing.T,
	cfg *tls.Config,
	wantMinVersion uint16,
	wantCipherSuites []uint16,
	wantCurvePreferences []tls.CurveID,
) {
	t.Helper()

	require.NotNil(t, cfg)
	require.Equal(t, wantMinVersion, cfg.MinVersion)
	require.Equal(t, wantCipherSuites, cfg.CipherSuites)
	require.Equal(t, wantCurvePreferences, cfg.CurvePreferences)
}

func TestNewProvider(t *testing.T) {
	tests := map[string]struct {
		opts    Options
		expErr  string
		expFail bool
	}{
		"if no TLS options are set, provider is created successfully": {
			opts: Options{},
		},
		"if explicit cipher suites are set, provider is created successfully": {
			opts: Options{
				ServingTLSCipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			},
		},
		"if explicit curve preferences are set, provider is created successfully": {
			opts: Options{
				ServingTLSCurvePreferences: []string{"X25519"},
			},
		},
		"if an invalid cipher suite is set, return error": {
			opts: Options{
				ServingTLSCipherSuites: []string{"NOT_A_CIPHER_SUITE"},
			},
			expFail: true,
		},
		"if an invalid min TLS version name is set, return error": {
			opts: Options{
				ServingTLSMinVersion: "VersionTLS0xBAD",
			},
			expFail: true,
		},
		"if min TLS version is below 1.2, return error": {
			opts: Options{
				ServingTLSMinVersion: "VersionTLS11",
			},
			expErr:  "serving tls min version must be VersionTLS12 or higher",
			expFail: true,
		},
		"if an invalid curve preference is set, return error": {
			opts: Options{
				ServingTLSCurvePreferences: []string{"not-a-curve"},
			},
			expFail: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := NewProvider(logr.Discard(), cmfake.New(), test.opts, stubIssuerNotifier{})
			if test.expFail {
				if test.expErr != "" {
					require.EqualError(t, err, test.expErr)
					return
				}
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, p)
		})
	}
}

func TestProviderServingTLSConfig(t *testing.T) {
	caCert, caKey := mustTestCA(t)
	signer := testSigner(t, caCert, caKey)

	wantCipherSuites, err := cliflag.TLSCipherSuites([]string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"})
	require.NoError(t, err)

	tests := map[string]struct {
		opts                 Options
		wantMinVersion       uint16
		wantCipherSuites     []uint16
		wantCurvePreferences []tls.CurveID
	}{
		"if no serving TLS options are set, apply Go defaults to returned tls.Config": {
			opts: Options{
				TrustDomain:                "cluster.local",
				ServingCertificateDuration: time.Hour,
				ServingCertificateDNSNames: []string{"localhost"},
				ServingSignatureAlgorithm:  "RSA",
				ServingCertificateKeySize:  2048,
			},
			wantMinVersion: tls.VersionTLS12,
		},
		"if cipher suites and curve preferences are set, apply them to returned tls.Config": {
			opts: Options{
				TrustDomain:                "cluster.local",
				ServingCertificateDuration: time.Hour,
				ServingCertificateDNSNames: []string{"localhost"},
				ServingSignatureAlgorithm:  "RSA",
				ServingCertificateKeySize:  2048,
				ServingTLSCipherSuites:     []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
				ServingTLSCurvePreferences: []string{"X25519"},
			},
			wantMinVersion:       tls.VersionTLS12,
			wantCipherSuites:     wantCipherSuites,
			wantCurvePreferences: []tls.CurveID{tls.X25519},
		},
		"if min TLS version is set, apply it to returned tls.Config": {
			opts: Options{
				TrustDomain:                "cluster.local",
				ServingCertificateDuration: time.Hour,
				ServingCertificateDNSNames: []string{"localhost"},
				ServingSignatureAlgorithm:  "RSA",
				ServingCertificateKeySize:  2048,
				ServingTLSMinVersion:       "VersionTLS13",
			},
			wantMinVersion: tls.VersionTLS13,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := NewProvider(logr.Discard(), signer, test.opts, stubIssuerNotifier{})
			require.NoError(t, err)

			_, err = p.fetchCertificate(context.Background())
			require.NoError(t, err)

			inner, err := p.getConfigForClient(nil)
			require.NoError(t, err)
			assertServingTLSConfig(t, inner, test.wantMinVersion, test.wantCipherSuites, test.wantCurvePreferences)

			outer, err := p.Config(context.Background())
			require.NoError(t, err)
			assertServingTLSConfig(t, outer, test.wantMinVersion, test.wantCipherSuites, test.wantCurvePreferences)
			require.NotNil(t, outer.GetConfigForClient)
		})
	}
}
