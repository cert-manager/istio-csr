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
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
	securityapi "istio.io/api/security/v1alpha1"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/security"
	testUtil "istio.io/istio/pkg/test"
	"istio.io/istio/pkg/util/sets"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2/ktesting"

	"github.com/cert-manager/istio-csr/test/gen"
)

func TestIdentitiesMatch(t *testing.T) {
	tests := map[string]struct {
		aList, bURL []string
		expMatch    bool
	}{
		"if both are empty then true": {
			aList:    nil,
			bURL:     nil,
			expMatch: true,
		},
		"if aList has identity, bURL not, false": {
			aList:    []string{"spiffee://foo.bar"},
			bURL:     nil,
			expMatch: false,
		},
		"if aList has no identity, bURL does, false": {
			aList:    nil,
			bURL:     []string{"spiffe://foo.bar"},
			expMatch: false,
		},
		"if aList one identity, bURL has the same, true": {
			aList:    []string{"spiffe://foo.bar"},
			bURL:     []string{"spiffe://foo.bar"},
			expMatch: true,
		},
		"if aList one identity, bURL has different, false": {
			aList:    []string{"spiffe://123.456"},
			bURL:     []string{"spiffe://foo.bar"},
			expMatch: false,
		},
		"if aList two identities, bURL has same, true": {
			aList:    []string{"spiffe://123.456", "spiffe://foo.bar"},
			bURL:     []string{"spiffe://123.456", "spiffe://foo.bar"},
			expMatch: true,
		},
		"if aList two identities, bURL has same but different order, true": {
			aList:    []string{"spiffe://123.456", "spiffe://foo.bar"},
			bURL:     []string{"spiffe://foo.bar", "spiffe://123.456"},
			expMatch: true,
		},
		"if aList two identities, bURL has different, false": {
			aList:    []string{"spiffe://123.456", "spiffe://foo.bar"},
			bURL:     []string{"spiffe://123.456", "spiffe://bar.foo"},
			expMatch: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var urls []*url.URL
			for _, burl := range test.bURL {
				url, err := url.Parse(burl)
				if err != nil {
					t.Fatal(err)
				}

				urls = append(urls, url)
			}

			if match := identitiesMatch(test.aList, urls); match != test.expMatch {
				t.Errorf("unexpected match, exp=%t got=%t (%+v %+v)",
					test.expMatch, match, test.aList, urls)
			}
		})
	}
}

type mockAuthenticator struct {
	identities     []string
	kubernetesInfo security.KubernetesInfo
	errMsg         string
}

func (authn *mockAuthenticator) AuthenticatorType() string {
	return "mockAuthenticator"
}

func (authn *mockAuthenticator) Authenticate(ctx security.AuthContext) (*security.Caller, error) {
	if len(authn.errMsg) > 0 {
		return nil, fmt.Errorf("%v", authn.errMsg)
	}

	return &security.Caller{
		Identities:     authn.identities,
		KubernetesInfo: authn.kubernetesInfo,
	}, nil
}

func (authn *mockAuthenticator) AuthenticateRequest(_ *http.Request) (*security.Caller, error) {
	return nil, fmt.Errorf("not implemented")
}

func newMockAuthn(ids []string, errMsg string) *mockAuthenticator {
	return &mockAuthenticator{
		identities: ids,
		errMsg:     errMsg,
	}
}

func newMockAuthnImpersonate(ids []string, kubeInfo *security.KubernetesInfo) *mockAuthenticator {
	return &mockAuthenticator{
		identities:     ids,
		kubernetesInfo: *kubeInfo,
	}
}

func newistioRequestMetadata(identity pod) *structpb.Struct {
	reqMeta, _ := structpb.NewStruct(map[string]any{
		security.ImpersonatedIdentity: identity.Identity(),
	})
	return reqMeta
}

// See original code: https://github.com/istio/istio/blob/1.22.3/security/pkg/server/ca/server_test.go
// See license of original code: https://github.com/istio/istio/blob/1.22.3/LICENSE
func TestAuthRequestImpersonation(t *testing.T) {
	allowZtunnel := map[types.NamespacedName]struct{}{
		{Name: "ztunnel", Namespace: "istio-system"}: {},
	}
	ztunnelCaller := security.KubernetesInfo{
		PodName:           "ztunnel-a",
		PodNamespace:      "istio-system",
		PodUID:            "12345",
		PodServiceAccount: "ztunnel",
	}
	ztunnelPod := pod{
		name:      ztunnelCaller.PodName,
		namespace: ztunnelCaller.PodNamespace,
		account:   ztunnelCaller.PodServiceAccount,
		uid:       ztunnelCaller.PodUID,
		node:      "zt-node",
	}
	podSameNode := pod{
		name:      "pod-a",
		namespace: "ns-a",
		account:   "sa-a",
		uid:       "1",
		node:      "zt-node",
	}
	tests := map[string]struct {
		authns              []security.Authenticator
		inpCSR              string
		reqMeta             *structpb.Struct
		trustedNodeAccounts sets.Set[types.NamespacedName]
		pods                []pod
		expIdenties         string
		expAuth             bool
	}{
		"if impersonating, and auth returns no error, and given csr matches id, return identities and true": {
			authns: []security.Authenticator{newMockAuthnImpersonate(
				[]string{ztunnelPod.Identity()},
				&ztunnelCaller)},
			inpCSR: string(gen.MustCSR(t,
				gen.SetCSRIdentities([]string{podSameNode.Identity()}),
			)),
			reqMeta:             newistioRequestMetadata(podSameNode),
			trustedNodeAccounts: allowZtunnel,
			pods:                []pod{ztunnelPod, podSameNode},
			expIdenties:         podSameNode.Identity(),
			expAuth:             true,
		},
		"if impersonating, and auth returns error, return no identities and error": {
			authns: []security.Authenticator{newMockAuthnImpersonate(
				[]string{ztunnelPod.Identity()},
				&ztunnelCaller)},
			inpCSR: string(gen.MustCSR(t,
				gen.SetCSRIdentities([]string{podSameNode.Identity()}),
			)),
			reqMeta:             newistioRequestMetadata(podSameNode),
			trustedNodeAccounts: map[types.NamespacedName]struct{}{},
			pods:                []pod{ztunnelPod, podSameNode},
			expIdenties:         "",
			expAuth:             false,
		},
		"if impersonating, and auth ok, but csr has different identities, return no identities and error": {
			authns: []security.Authenticator{newMockAuthnImpersonate(
				[]string{ztunnelPod.Identity()},
				&ztunnelCaller)},
			inpCSR: string(gen.MustCSR(t,
				gen.SetCSRIdentities([]string{ztunnelPod.Identity()}),
			)),
			reqMeta:             newistioRequestMetadata(podSameNode),
			trustedNodeAccounts: allowZtunnel,
			pods:                []pod{ztunnelPod, podSameNode},
			expIdenties:         podSameNode.Identity(),
			expAuth:             false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var pods []runtime.Object
			for _, p := range test.pods {
				pods = append(pods, &v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      p.name,
						Namespace: p.namespace,
						UID:       types.UID(p.uid),
					},
					Spec: v1.PodSpec{
						ServiceAccountName: p.account,
						NodeName:           p.node,
					},
				})
			}
			c := kube.NewFakeClient(pods...)
			na := NewClusterNodeAuthorizer(c, test.trustedNodeAccounts)
			c.RunAndWait(testUtil.NewStop(t))
			kube.WaitForCacheSync("test", testUtil.NewStop(t), na.pods.HasSynced)

			s := &Server{
				log:            ktesting.NewLogger(t, ktesting.DefaultConfig),
				authenticators: test.authns,
				nodeAuthorizer: na,
			}

			icr := &securityapi.IstioCertificateRequest{
				Csr:              test.inpCSR,
				Metadata:         test.reqMeta,
				ValidityDuration: 60 * 30,
			}

			identities, authed := s.authRequest(context.TODO(), icr)
			if identities != test.expIdenties {
				t.Errorf("unexpected identities response, exp=%s got=%s",
					test.expIdenties, identities)
			}

			if authed != test.expAuth {
				t.Errorf("unexpected authed response, exp=%t got=%t",
					test.expAuth, authed)
			}
		})
	}
}

func TestAuthRequest(t *testing.T) {
	tests := map[string]struct {
		authns      []security.Authenticator
		icr         func(t *testing.T) *securityapi.IstioCertificateRequest
		expIdenties string
		expAuth     bool
	}{
		"is auth errors, return empty and false": {
			authns: []security.Authenticator{newMockAuthn(nil, "an error")},
			icr: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return &securityapi.IstioCertificateRequest{
					Csr: "",
				}
			},
			expIdenties: "",
			expAuth:     false,
		},
		"if auth returns no identities, error": {
			authns: []security.Authenticator{newMockAuthn(nil, "")},
			icr: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return &securityapi.IstioCertificateRequest{
					Csr: "",
				}
			},
			expIdenties: "",
			expAuth:     false,
		},
		"if auth returns identities, but given csr is bad ecoded, error": {
			authns: []security.Authenticator{newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, "")},
			icr: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return &securityapi.IstioCertificateRequest{
					Csr: "bad csr",
				}
			},
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has dns, error": {
			authns: []security.Authenticator{newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, "")},
			icr: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return &securityapi.IstioCertificateRequest{
					Csr: string(gen.MustCSR(t,
						gen.SetCSRIdentities([]string{"spiffe://foo", "spiffe://bar"}),
						gen.SetCSRDNS([]string{"example.com", "jetstack.io"}),
					)),
				}
			},
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has ips, error": {
			authns: []security.Authenticator{newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, "")},
			icr: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return &securityapi.IstioCertificateRequest{
					Csr: string(gen.MustCSR(t,
						gen.SetCSRIdentities([]string{"spiffe://foo", "spiffe://bar"}),
						gen.SetCSRIPs([]string{"8.8.8.8"}),
					)),
				}
			},
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has common name, error": {
			authns: []security.Authenticator{newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, "")},
			icr: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return &securityapi.IstioCertificateRequest{
					Csr: string(gen.MustCSR(t,
						gen.SetCSRIdentities([]string{"spiffe://foo", "spiffe://bar"}),
						gen.SetCSRCommonName("jetstack.io"),
					)),
				}
			},
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has email addresses, error": {
			authns: []security.Authenticator{newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, "")},
			icr: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return &securityapi.IstioCertificateRequest{
					Csr: string(gen.MustCSR(t,
						gen.SetCSRIdentities([]string{"spiffe://foo", "spiffe://bar"}),
						gen.SetCSREmails([]string{"joshua.vanleeuwen@jetstack.io"}),
					)),
				}
			},
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has miss matched identities, error": {
			authns: []security.Authenticator{newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, "")},
			icr: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return &securityapi.IstioCertificateRequest{
					Csr: string(gen.MustCSR(t,
						gen.SetCSRIdentities([]string{"spiffe://josh", "spiffe://bar"}),
					)),
				}
			},
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has subset of identities, error": {
			authns: []security.Authenticator{newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, "")},
			icr: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return &securityapi.IstioCertificateRequest{
					Csr: string(gen.MustCSR(t,
						gen.SetCSRIdentities([]string{"spiffe://bar"}),
					)),
				}
			},
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has more identities, error": {
			authns: []security.Authenticator{newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, "")},
			icr: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return &securityapi.IstioCertificateRequest{
					Csr: string(gen.MustCSR(t,
						gen.SetCSRIdentities([]string{"spiffe://foo", "spiffe://bar", "spiffe://joshua.vanleeuwen"}),
					)),
				}
			},
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, and given csr matches identities, return true": {
			authns: []security.Authenticator{newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, "")},
			icr: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return &securityapi.IstioCertificateRequest{
					Csr: string(gen.MustCSR(t,
						gen.SetCSRIdentities([]string{"spiffe://foo", "spiffe://bar"}),
					)),
				}
			},
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     true,
		},
		"if auth returns single id, and given csr matches id, return true": {
			authns: []security.Authenticator{newMockAuthn([]string{"spiffe://foo"}, "")},
			icr: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return &securityapi.IstioCertificateRequest{
					Csr: string(gen.MustCSR(t,
						gen.SetCSRIdentities([]string{"spiffe://foo"}),
					)),
				}
			},
			expIdenties: "spiffe://foo",
			expAuth:     true,
		},
		"if one auth is successful, but another isn't, return true": {
			authns: []security.Authenticator{
				newMockAuthn([]string{"spiffe://foo"}, ""),
				newMockAuthn(nil, "an error"),
			},
			icr: func(t *testing.T) *securityapi.IstioCertificateRequest {
				return &securityapi.IstioCertificateRequest{
					Csr: string(gen.MustCSR(t,
						gen.SetCSRIdentities([]string{"spiffe://foo"}),
					)),
				}
			},
			expIdenties: "spiffe://foo",
			expAuth:     true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			s := &Server{
				log:            ktesting.NewLogger(t, ktesting.DefaultConfig),
				authenticators: test.authns,
			}

			identities, authed := s.authRequest(context.TODO(), test.icr(t))
			if identities != test.expIdenties {
				t.Errorf("unexpected identities response, exp=%s got=%s",
					test.expIdenties, identities)
			}

			if authed != test.expAuth {
				t.Errorf("unexpected authed response, exp=%t got=%t",
					test.expAuth, authed)
			}
		})
	}
}
