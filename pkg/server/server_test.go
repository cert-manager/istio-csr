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

package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	securityapi "istio.io/api/security/v1alpha1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/klog/v2/klogr"

	"github.com/cert-manager/istio-csr/pkg/certmanager"
	cmfake "github.com/cert-manager/istio-csr/pkg/certmanager/fake"
	"github.com/cert-manager/istio-csr/pkg/tls"
	tlsfake "github.com/cert-manager/istio-csr/pkg/tls/fake"
	"github.com/cert-manager/istio-csr/test/gen"
)

func Test_CreateCertificate(t *testing.T) {
	const spiffeDomain = "spiffe://foo"

	rootPK, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}
	rootCert := &x509.Certificate{
		Version:               2,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(0),
		Subject: pkix.Name{
			CommonName: "root-ca",
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

	leafPK, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}
	leafCertPEM, _, err := pki.SignCertificate(&x509.Certificate{
		Version: 2, BasicConstraintsValid: true, SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName: "leaf-cert",
		},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Minute),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		PublicKey: leafPK.Public(), IsCA: false,
	}, rootCert, leafPK.Public(), rootPK)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		icr func(t *testing.T) *securityapi.IstioCertificateRequest

		cm          func(t *testing.T) certmanager.Signer
		tls         tls.Interface
		maxDuration time.Duration

		expResponse *securityapi.IstioCertificateResponse
		expErr      error
	}{
		"if authn fails, should return Unauthenticated error code": {
			icr: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return &securityapi.IstioCertificateRequest{
					Csr: string(gen.MustCSR(t,
						gen.SetCSRIdentities([]string{"spiffe://bar"}),
					)),
				}
			},
			cm:          func(t *testing.T) certmanager.Signer { return cmfake.New() },
			expResponse: nil,
			expErr:      status.Error(codes.Unauthenticated, "request authenticate failure"),
		},
		"if authn succeeds but sign fails, should return Internal error code": {
			icr: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return &securityapi.IstioCertificateRequest{
					Csr: string(gen.MustCSR(t,
						gen.SetCSRIdentities([]string{spiffeDomain}),
					)),
				}
			},
			cm: func(t *testing.T) certmanager.Signer {
				return cmfake.New().WithSign(func(_ context.Context, identity string, _ []byte, _ time.Duration, _ []cmapi.KeyUsage) (certmanager.Bundle, error) {
					if identity != spiffeDomain {
						t.Errorf("unexpected identity, exp=%s got=%s", spiffeDomain, identity)
					}
					return certmanager.Bundle{}, errors.New("generic error")
				})
			},
			maxDuration: time.Hour,
			expResponse: nil,
			expErr:      status.Error(codes.Internal, "failed to sign certificate request"),
		},
		"if authn and sign succeeds, should sign certificate with given duration and respond": {
			icr: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return &securityapi.IstioCertificateRequest{
					Csr: string(gen.MustCSR(t,
						gen.SetCSRIdentities([]string{spiffeDomain}),
					)),
					ValidityDuration: 60 * 30,
				}
			},
			cm: func(t *testing.T) certmanager.Signer {
				return cmfake.New().WithSign(func(_ context.Context, identity string, _ []byte, dur time.Duration, _ []cmapi.KeyUsage) (certmanager.Bundle, error) {
					if identity != spiffeDomain {
						t.Errorf("unexpected identity, exp=%s got=%s", spiffeDomain, identity)
					}

					if dur != time.Minute*30 {
						t.Errorf("unexpected requested duration, exp=%s got=%s", time.Minute*30, dur)
					}

					return certmanager.Bundle{Certificate: leafCertPEM, CA: []byte("bad-cert")}, nil
				})
			},
			tls:         tlsfake.New().WithRootCAs(rootCertPEM, rootPool),
			maxDuration: time.Hour * 2,
			expResponse: &securityapi.IstioCertificateResponse{CertChain: []string{string(leafCertPEM), string(rootCertPEM)}},
			expErr:      nil,
		},
		"if authn and sign succeeds, should sign certificate with maximum duration and respond": {
			icr: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return &securityapi.IstioCertificateRequest{
					Csr: string(gen.MustCSR(t,
						gen.SetCSRIdentities([]string{spiffeDomain}),
					)),
					ValidityDuration: 60 * 60,
				}
			},
			cm: func(t *testing.T) certmanager.Signer {
				return cmfake.New().WithSign(func(_ context.Context, identity string, _ []byte, dur time.Duration, _ []cmapi.KeyUsage) (certmanager.Bundle, error) {
					if identity != spiffeDomain {
						t.Errorf("unexpected identity, exp=%s got=%s", spiffeDomain, identity)
					}

					if dur != time.Hour/2 {
						t.Errorf("unexpected requested duration, exp=%s got=%s", time.Hour/2, dur)
					}

					return certmanager.Bundle{Certificate: leafCertPEM, CA: []byte("bad-cert")}, nil
				})
			},
			tls:         tlsfake.New().WithRootCAs(rootCertPEM, rootPool),
			maxDuration: time.Hour / 2,
			expResponse: &securityapi.IstioCertificateResponse{CertChain: []string{string(leafCertPEM), string(rootCertPEM)}},
			expErr:      nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			s := &Server{
				opts: Options{
					MaximumClientCertificateDuration: test.maxDuration,
				},
				auther: newMockAuthn([]string{spiffeDomain}, ""),
				log:    klogr.New(),
				cm:     test.cm(t),
				tls:    test.tls,
			}

			resp, err := s.CreateCertificate(context.TODO(), test.icr(t))
			errS, _ := status.FromError(err)
			expErrS, _ := status.FromError(test.expErr)

			if !proto.Equal(errS.Proto(), expErrS.Proto()) {
				t.Errorf("unexpected error, exp=%v got=%v", test.expErr, err)
			}

			if !apiequality.Semantic.DeepEqual(resp, test.expResponse) {
				t.Errorf("unexpected response, exp=%v got=%v", test.expResponse, resp)
			}
		})
	}
}

type testBundle struct {
	cert *x509.Certificate
	pem  []byte
	pk   crypto.PrivateKey
}

func mustCreateBundle(t *testing.T, issuer *testBundle, name string) *testBundle {
	pk, err := pki.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		Version:               3,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    x509.ECDSA,
		PublicKey:             pk.Public(),
		IsCA:                  true,
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	var (
		issuerKey  crypto.PrivateKey
		issuerCert *x509.Certificate
	)

	if issuer == nil {
		// No issuer implies the cert should be self signed
		issuerKey = pk
		issuerCert = template
	} else {
		issuerKey = issuer.pk
		issuerCert = issuer.cert
	}

	certPEM, cert, err := pki.SignCertificate(template, issuerCert, pk.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}

	return &testBundle{pem: certPEM, cert: cert, pk: pk}
}

func joinPEM(first []byte, rest ...[]byte) []byte {
	for _, b := range rest {
		first = append(first, b...)
	}

	return first
}

func Test_parseCertificateBundle(t *testing.T) {
	root1 := mustCreateBundle(t, nil, "root")
	root2 := mustCreateBundle(t, nil, "root2")
	root3 := mustCreateBundle(t, nil, "root3")
	int1A := mustCreateBundle(t, root1, "intA-1")
	int1B := mustCreateBundle(t, int1A, "intA-2")
	int2A := mustCreateBundle(t, root2, "intB-1")
	leaf := mustCreateBundle(t, int1B, "leaf")

	tests := map[string]struct {
		bundle    certmanager.Bundle
		rootCerts func(t *testing.T) ([]byte, *x509.CertPool)
		expChain  []string
		expErr    bool
	}{
		"if chain contains garbage data, return error": {
			bundle:    certmanager.Bundle{Certificate: []byte("bad-cert")},
			rootCerts: func(t *testing.T) ([]byte, *x509.CertPool) { return nil, nil },
			expChain:  nil,
			expErr:    true,
		},
		"if chain is not a single chain then error": {
			bundle: certmanager.Bundle{Certificate: joinPEM(leaf.pem, int2A.pem)},
			rootCerts: func(t *testing.T) ([]byte, *x509.CertPool) {
				pool := x509.NewCertPool()
				pool.AddCert(root1.cert)
				pool.AddCert(root2.cert)
				pool.AddCert(root3.cert)
				return joinPEM(root1.pem, root2.pem, root3.pem), pool
			},
			expChain: nil,
			expErr:   true,
		},
		"if chain does not originate from a current root, error": {
			bundle: certmanager.Bundle{Certificate: joinPEM(leaf.pem, int1B.pem, int1A.pem)},
			rootCerts: func(t *testing.T) ([]byte, *x509.CertPool) {
				pool := x509.NewCertPool()
				pool.AddCert(root2.cert)
				pool.AddCert(root3.cert)
				return joinPEM(root2.pem, root3.pem), pool
			},
			expChain: nil,
			expErr:   true,
		},
		"if chain originates from the root, return single chain": {
			bundle: certmanager.Bundle{Certificate: joinPEM(leaf.pem, int1B.pem, int1A.pem)},
			rootCerts: func(t *testing.T) ([]byte, *x509.CertPool) {
				pool := x509.NewCertPool()
				pool.AddCert(root1.cert)
				return root1.pem, pool
			},
			expChain: []string{string(leaf.pem), string(int1B.pem), string(int1A.pem), string(root1.pem)},
			expErr:   false,
		},
		"if chain originates from the root, return chain with all roots": {
			bundle: certmanager.Bundle{Certificate: joinPEM(leaf.pem, int1B.pem, int1A.pem)},
			rootCerts: func(t *testing.T) ([]byte, *x509.CertPool) {
				pool := x509.NewCertPool()
				pool.AddCert(root1.cert)
				pool.AddCert(root2.cert)
				pool.AddCert(root3.cert)
				return joinPEM(root1.pem, root2.pem, root3.pem), pool
			},
			expChain: []string{string(leaf.pem), string(int1B.pem), string(int1A.pem), string(root1.pem) + string(root2.pem) + string(root3.pem)},
			expErr:   false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			rootCAsPEM, rootCAsPool := test.rootCerts(t)
			s := &Server{
				tls: tlsfake.New().WithRootCAs(rootCAsPEM, rootCAsPool),
			}

			chain, err := s.parseCertificateBundle(test.bundle)
			assert.Equalf(t, test.expErr, err != nil, "%v", err)
			assert.Equal(t, test.expChain, chain)
		})
	}
}
