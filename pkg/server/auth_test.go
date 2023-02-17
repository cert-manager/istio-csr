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

	"istio.io/istio/pkg/security"
	"k8s.io/klog/v2/klogr"

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
	identities []string
	errMsg     string
}

func (authn *mockAuthenticator) AuthenticatorType() string {
	return "mockAuthenticator"
}

func (authn *mockAuthenticator) Authenticate(ctx security.AuthContext) (*security.Caller, error) {
	if len(authn.errMsg) > 0 {
		return nil, fmt.Errorf("%v", authn.errMsg)
	}

	return &security.Caller{
		Identities: authn.identities,
	}, nil
}

func (authn *mockAuthenticator) AuthenticateRequest(_ *http.Request) (*security.Caller, error) {
	return nil, nil
}

func newMockAuthn(ids []string, errMsg string) *mockAuthenticator {
	return &mockAuthenticator{
		identities: ids,
		errMsg:     errMsg,
	}
}

func TestAuthRequest(t *testing.T) {
	tests := map[string]struct {
		authn       *mockAuthenticator
		inpCSR      []byte
		expIdenties string
		expAuth     bool
	}{
		"is auth errors, return empty and false": {
			authn:       newMockAuthn(nil, "an error"),
			inpCSR:      nil,
			expIdenties: "",
			expAuth:     false,
		},
		"if auth returns no identities, error": {
			authn:       newMockAuthn(nil, ""),
			inpCSR:      nil,
			expIdenties: "",
			expAuth:     false,
		},
		"if auth returns identities, but given csr is bad ecoded, error": {
			authn:       newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, ""),
			inpCSR:      []byte("bad csr"),
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has dns, error": {
			authn: newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, ""),
			inpCSR: gen.MustCSR(t,
				gen.SetCSRIdentities([]string{"spiffe://foo", "spiffe://bar"}),
				gen.SetCSRDNS([]string{"example.com", "jetstack.io"}),
			),
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has ips, error": {
			authn: newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, ""),
			inpCSR: gen.MustCSR(t,
				gen.SetCSRIdentities([]string{"spiffe://foo", "spiffe://bar"}),
				gen.SetCSRIPs([]string{"8.8.8.8"}),
			),
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has common name, error": {
			authn: newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, ""),
			inpCSR: gen.MustCSR(t,
				gen.SetCSRIdentities([]string{"spiffe://foo", "spiffe://bar"}),
				gen.SetCSRCommonName("jetstack.io"),
			),
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has email addresses, error": {
			authn: newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, ""),
			inpCSR: gen.MustCSR(t,
				gen.SetCSRIdentities([]string{"spiffe://foo", "spiffe://bar"}),
				gen.SetCSREmails([]string{"joshua.vanleeuwen@jetstack.io"}),
			),
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has miss matched identities, error": {
			authn: newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, ""),
			inpCSR: gen.MustCSR(t,
				gen.SetCSRIdentities([]string{"spiffe://josh", "spiffe://bar"}),
			),
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has subset of identities, error": {
			authn: newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, ""),
			inpCSR: gen.MustCSR(t,
				gen.SetCSRIdentities([]string{"spiffe://bar"}),
			),
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has more identities, error": {
			authn: newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, ""),
			inpCSR: gen.MustCSR(t,
				gen.SetCSRIdentities([]string{"spiffe://foo", "spiffe://bar", "spiffe://joshua.vanleeuwen"}),
			),
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, and given csr matches identities, return true": {
			authn: newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, ""),
			inpCSR: gen.MustCSR(t,
				gen.SetCSRIdentities([]string{"spiffe://foo", "spiffe://bar"}),
			),
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     true,
		},
		"if auth returns single id, and given csr matches id, return true": {
			authn: newMockAuthn([]string{"spiffe://foo"}, ""),
			inpCSR: gen.MustCSR(t,
				gen.SetCSRIdentities([]string{"spiffe://foo"}),
			),
			expIdenties: "spiffe://foo",
			expAuth:     true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			s := &Server{
				log:    klogr.New(),
				auther: test.authn,
			}

			identities, authed := s.authRequest(context.TODO(), test.inpCSR)
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
