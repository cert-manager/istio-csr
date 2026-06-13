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
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/stretchr/testify/assert"
	"k8s.io/klog/v2/ktesting"

	"github.com/cert-manager/istio-csr/pkg/tls/rootca"
)

func Test_NewProvider(t *testing.T) {
	tests := map[string]struct {
		opts            Options
		expTrustDomain  string
		expDNSNames     []string
		expKeySize      int
		expSigAlgorithm string
	}{
		"should store all options correctly": {
			opts: Options{
				TrustDomain:                "cluster.local",
				ServingCertificateDNSNames: []string{"istio-csr.cert-manager.svc"},
				ServingCertificateKeySize:  2048,
				ServingSignatureAlgorithm:  "RSA",
				ServingCertificateDuration: time.Hour,
			},
			expTrustDomain:  "cluster.local",
			expDNSNames:     []string{"istio-csr.cert-manager.svc"},
			expKeySize:      2048,
			expSigAlgorithm: "RSA",
		},
		"should handle custom trust domain": {
			opts: Options{
				TrustDomain:                "example.org",
				ServingCertificateDNSNames: []string{"a.example.org", "b.example.org"},
				ServingCertificateKeySize:  4096,
				ServingSignatureAlgorithm:  "ECDSA",
				ServingCertificateDuration: 24 * time.Hour,
			},
			expTrustDomain:  "example.org",
			expDNSNames:     []string{"a.example.org", "b.example.org"},
			expKeySize:      4096,
			expSigAlgorithm: "ECDSA",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := NewProvider(ktesting.NewLogger(t, ktesting.DefaultConfig), nil, test.opts, nil)
			assert.NoError(t, err)
			assert.Equal(t, test.expTrustDomain, p.opts.TrustDomain)
			assert.Equal(t, test.expDNSNames, p.opts.ServingCertificateDNSNames)
			assert.Equal(t, test.expKeySize, p.opts.ServingCertificateKeySize)
			assert.Equal(t, test.expSigAlgorithm, p.opts.ServingSignatureAlgorithm)
		})
	}
}

func Test_TrustDomain(t *testing.T) {
	tests := map[string]struct {
		trustDomain string
		expected    string
	}{
		"should return configured trust domain": {
			trustDomain: "cluster.local",
			expected:    "cluster.local",
		},
		"should return custom trust domain": {
			trustDomain: "my-mesh.example.com",
			expected:    "my-mesh.example.com",
		},
		"should return empty string when not configured": {
			trustDomain: "",
			expected:    "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Provider{opts: Options{TrustDomain: test.trustDomain}}
			assert.Equal(t, test.expected, p.TrustDomain())
		})
	}
}

func Test_NeedLeaderElection(t *testing.T) {
	p := &Provider{}
	assert.False(t, p.NeedLeaderElection(), "NeedLeaderElection should return false so all replicas keep serving certs up to date")
}

func Test_Check(t *testing.T) {
	tests := map[string]struct {
		setConfig bool
		expErr    bool
	}{
		"if tlsConfig is nil, should return error": {
			setConfig: false,
			expErr:    true,
		},
		"if tlsConfig is set, should return nil": {
			setConfig: true,
			expErr:    false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Provider{}
			if test.setConfig {
				p.tlsConfig = &cryptotls.Config{}
			}

			err := p.Check(&http.Request{})
			assert.Equalf(t, test.expErr, err != nil, "%v", err)
		})
	}
}

func Test_SubscribeRootCAsEvent(t *testing.T) {
	t.Run("should return a unique channel for each subscriber", func(t *testing.T) {
		p := &Provider{}

		ch1 := p.SubscribeRootCAsEvent()
		ch2 := p.SubscribeRootCAsEvent()
		ch3 := p.SubscribeRootCAsEvent()

		assert.NotNil(t, ch1)
		assert.NotNil(t, ch2)
		assert.NotNil(t, ch3)
		assert.Len(t, p.subscriptions, 3)

		// Verify channels are distinct
		assert.NotEqual(t, ch1, ch2)
		assert.NotEqual(t, ch2, ch3)
	})
}

func Test_getConfigForClient(t *testing.T) {
	t.Run("should return current tlsConfig", func(t *testing.T) {
		expectedConfig := &cryptotls.Config{MinVersion: cryptotls.VersionTLS13}
		p := &Provider{tlsConfig: expectedConfig}

		result, err := p.getConfigForClient(nil)
		assert.NoError(t, err)
		assert.Equal(t, expectedConfig, result)
	})

	t.Run("should return nil when tlsConfig is not set", func(t *testing.T) {
		p := &Provider{}

		result, err := p.getConfigForClient(nil)
		assert.NoError(t, err)
		assert.Nil(t, result)
	})
}

func Test_loadCAsRoot(t *testing.T) {
	rootCAs1 := genTestRootCAs(t)
	rootCAs2 := genTestRootCAs(t)

	tests := map[string]struct {
		existingPEM []byte
		newPEM      []byte
		expErr      bool
		expUpdated  bool
	}{
		"should load valid CA PEM and update rootCAs": {
			existingPEM: nil,
			newPEM:      rootCAs1.PEM,
			expErr:      false,
			expUpdated:  true,
		},
		"should be a no-op when PEM has not changed": {
			existingPEM: rootCAs1.PEM,
			newPEM:      rootCAs1.PEM,
			expErr:      false,
			expUpdated:  false,
		},
		"should update when PEM changes": {
			existingPEM: rootCAs1.PEM,
			newPEM:      rootCAs2.PEM,
			expErr:      false,
			expUpdated:  true,
		},
		"should return error for invalid PEM data": {
			existingPEM: nil,
			newPEM:      []byte("not-a-valid-certificate"),
			expErr:      true,
			expUpdated:  false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := &Provider{}
			if test.existingPEM != nil {
				p.rootCAs = rootca.RootCAs{PEM: test.existingPEM}
			}

			err := p.loadCAsRoot(test.newPEM)
			assert.Equalf(t, test.expErr, err != nil, "%v", err)

			if test.expUpdated {
				assert.Equal(t, test.newPEM, p.rootCAs.PEM)
				assert.NotNil(t, p.rootCAs.CertPool)
			}
		})
	}
}

func Test_loadCAsRoot_broadcasts_to_subscribers(t *testing.T) {
	rootCAs1 := genTestRootCAs(t)
	rootCAs2 := genTestRootCAs(t)

	p := &Provider{
		rootCAs: rootca.RootCAs{PEM: rootCAs1.PEM},
	}

	// Subscribe before loading
	ch := p.SubscribeRootCAsEvent()

	// Load a different CA — should broadcast
	err := p.loadCAsRoot(rootCAs2.PEM)
	assert.NoError(t, err)

	// Subscriber should receive an event
	select {
	case <-ch:
		// expected
	case <-time.After(2 * time.Second):
		t.Fatal("expected broadcast event after root CA change, but timed out")
	}
}

func Test_loadCAsRoot_no_broadcast_when_unchanged(t *testing.T) {
	rootCAs1 := genTestRootCAs(t)

	p := &Provider{
		rootCAs: rootca.RootCAs{PEM: rootCAs1.PEM},
	}

	ch := p.SubscribeRootCAsEvent()

	// Load the same CA — should NOT broadcast
	err := p.loadCAsRoot(rootCAs1.PEM)
	assert.NoError(t, err)

	select {
	case <-ch:
		t.Fatal("unexpected broadcast event when root CA PEM has not changed")
	case <-time.After(100 * time.Millisecond):
		// expected — no event
	}
}

func Test_RootCAs(t *testing.T) {
	t.Run("should return rootCAs when populated", func(t *testing.T) {
		rootCAs := genTestRootCAs(t)
		p := &Provider{
			rootCAs: rootCAs,
		}

		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()

		result := p.RootCAs(ctx)
		assert.NotNil(t, result)
		assert.Equal(t, rootCAs.PEM, result.PEM)
		assert.True(t, rootCAs.CertPool.Equal(result.CertPool))
	})

	t.Run("should return nil when context is cancelled before rootCAs are available", func(t *testing.T) {
		p := &Provider{} // rootCAs not populated

		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()

		result := p.RootCAs(ctx)
		assert.Nil(t, result)
	})
}

func Test_Config(t *testing.T) {
	t.Run("should return tls config when available", func(t *testing.T) {
		p := &Provider{
			tlsConfig: &cryptotls.Config{MinVersion: cryptotls.VersionTLS12},
		}

		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()

		conf, err := p.Config(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, conf)
		assert.Equal(t, uint16(cryptotls.VersionTLS12), conf.MinVersion)
		assert.Equal(t, cryptotls.RequireAndVerifyClientCert, conf.ClientAuth)
		assert.NotNil(t, conf.GetConfigForClient)
	})

	t.Run("should return error when context is cancelled before config is available", func(t *testing.T) {
		p := &Provider{} // tlsConfig not set

		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()

		conf, err := p.Config(ctx)
		assert.Error(t, err)
		assert.Nil(t, conf)
	})
}

// genTestRootCAs generates a self-signed root CA certificate for testing.
func genTestRootCAs(t *testing.T) rootca.RootCAs {
	t.Helper()

	rootPK, err := pki.GenerateEd25519PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	rootCert := &x509.Certificate{
		Version:               2,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(0),
		Subject: pkix.Name{
			CommonName: "test-root-ca",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		PublicKey: rootPK.Public(),
		IsCA:      true,
	}
	rootCertPEM, rootCert, err := pki.SignCertificate(rootCert, rootCert, rootPK.Public(), rootPK)
	if err != nil {
		t.Fatal(err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	return rootca.RootCAs{PEM: rootCertPEM, CertPool: rootPool}
}
