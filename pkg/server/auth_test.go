package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/sirupsen/logrus"
	pkiutil "istio.io/istio/security/pkg/pki/util"
	"istio.io/istio/security/pkg/server/ca/authenticate"
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

func (authn *mockAuthenticator) Authenticate(ctx context.Context) (*authenticate.Caller, error) {
	if len(authn.errMsg) > 0 {
		return nil, fmt.Errorf("%v", authn.errMsg)
	}

	return &authenticate.Caller{
		Identities: authn.identities,
	}, nil
}

func genCSR(t *testing.T, ids, dns, ips, emails []string, cn string) []byte {
	opts := pkiutil.CertOptions{
		IsServer:   true,
		RSAKeySize: 2048,
	}

	csr, err := pkiutil.GenCSRTemplate(opts)
	if err != nil {
		t.Fatal(err)
	}

	for _, id := range ids {
		url, err := url.Parse(id)
		if err != nil {
			t.Fatal(err)
		}

		csr.URIs = append(csr.URIs, url)
	}

	for _, ip := range ips {
		csr.IPAddresses = append(csr.IPAddresses, net.ParseIP(ip))
	}

	csr.DNSNames = dns
	csr.EmailAddresses = emails
	csr.Subject.CommonName = cn

	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, sk)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
}

func TestAuthRequest(t *testing.T) {
	newMockAuthn := func(ids []string, errMsg string) *mockAuthenticator {
		return &mockAuthenticator{
			identities: ids,
			errMsg:     errMsg,
		}
	}

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
			inpCSR: genCSR(t,
				[]string{"spiffe://foo", "spiffe://bar"},
				[]string{"example.com", "jetstack.io"},
				nil,
				nil,
				"",
			),
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has ips, error": {
			authn: newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, ""),
			inpCSR: genCSR(t,
				[]string{"spiffe://foo", "spiffe://bar"},
				nil,
				[]string{"8.8.8.8"},
				nil,
				"",
			),
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has common name, error": {
			authn: newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, ""),
			inpCSR: genCSR(t,
				[]string{"spiffe://foo", "spiffe://bar"},
				nil,
				nil,
				nil,
				"jetstack.io",
			),
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has email addresses, error": {
			authn: newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, ""),
			inpCSR: genCSR(t,
				[]string{"spiffe://foo", "spiffe://bar"},
				nil,
				nil,
				[]string{"joshua.vanleeuwen@jetstack.io"},
				"",
			),
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has miss matched identities, error": {
			authn: newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, ""),
			inpCSR: genCSR(t,
				[]string{"spiffe://josh", "spiffe://bar"},
				nil,
				nil,
				nil,
				"",
			),
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has subset of identities, error": {
			authn: newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, ""),
			inpCSR: genCSR(t,
				[]string{"spiffe://bar"},
				nil,
				nil,
				nil,
				"",
			),
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, but given csr has more identities, error": {
			authn: newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, ""),
			inpCSR: genCSR(t,
				[]string{"spiffe://foo", "spiffe://bar", "spiffe://joshua.vanleeuwen"},
				nil,
				nil,
				nil,
				"",
			),
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     false,
		},
		"if auth returns identities, and given csr matches identities, return true": {
			authn: newMockAuthn([]string{"spiffe://foo", "spiffe://bar"}, ""),
			inpCSR: genCSR(t,
				[]string{"spiffe://foo", "spiffe://bar"},
				nil,
				nil,
				nil,
				"",
			),
			expIdenties: "spiffe://foo,spiffe://bar",
			expAuth:     true,
		},
		"if auth returns single id, and given csr matches id, return true": {
			authn: newMockAuthn([]string{"spiffe://foo"}, ""),
			inpCSR: genCSR(t,
				[]string{"spiffe://foo"},
				nil,
				nil,
				nil,
				"",
			),
			expIdenties: "spiffe://foo",
			expAuth:     true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			s := &Server{
				log:    logrus.NewEntry(logrus.New()),
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
