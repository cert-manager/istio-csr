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
	"errors"
	"testing"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	securityapi "istio.io/api/security/v1alpha1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/klog/v2/klogr"

	"github.com/cert-manager/istio-csr/pkg/certmanager"
	cmfake "github.com/cert-manager/istio-csr/pkg/certmanager/fake"
	"github.com/cert-manager/istio-csr/test/gen"
)

func Test_CreateCertificate(t *testing.T) {
	spiffeDomain := "spiffe://foo"

	tests := map[string]struct {
		icr func(t *testing.T) *securityapi.IstioCertificateRequest

		cm          func(t *testing.T) certmanager.Signer
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

					return certmanager.Bundle{Certificate: []byte("signed-cert"), CA: []byte("ca")}, nil
				})
			},
			maxDuration: time.Hour * 2,
			expResponse: &securityapi.IstioCertificateResponse{
				CertChain: []string{
					"signed-cert",
					"ca",
				},
			},
			expErr: nil,
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

					return certmanager.Bundle{Certificate: []byte("signed-cert"), CA: []byte("ca")}, nil
				})
			},
			maxDuration: time.Hour / 2,
			expResponse: &securityapi.IstioCertificateResponse{
				CertChain: []string{
					"signed-cert",
					"ca",
				},
			},
			expErr: nil,
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
