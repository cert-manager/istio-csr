package server

import (
	"context"
	"net/url"
	"sort"
	"strings"

	pkiutil "istio.io/istio/security/pkg/pki/util"
)

// authRequest will authenticate the request and authorize the CSR is valid for
// the identity
func (s *Server) authRequest(ctx context.Context, csrPEM []byte) (string, bool) {
	caller, err := s.auther.Authenticate(ctx)
	if err != nil {
		// TODO: pass in logger with request context
		s.log.Errorf("failed to authenticate request: %s", err)
		return "", false
	}

	// request authentication has no identities, so error
	if len(caller.Identities) == 0 {
		s.log.Error("request sent with no identity")
		return "", false
	}

	// return concatenated list of verified ids
	identities := strings.Join(caller.Identities, ",")

	csr, err := pkiutil.ParsePemEncodedCSR(csrPEM)
	if err != nil {
		s.log.Errorf("failed to decode CSR from %s: %s", identities, err)
		return identities, false
	}

	// if the csr contains any other options set, error
	if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 ||
		len(csr.Subject.CommonName) > 0 || len(csr.EmailAddresses) > 0 {
		s.log.Errorf("bad request from %s: DNS=%v IPs=%v CN=%s EMAIL=%v",
			identities, csr.DNSNames, csr.IPAddresses, csr.Subject.CommonName,
			csr.EmailAddresses)
		return identities, false
	}

	// ensure identity matches requests URIs
	if !identitiesMatch(caller.Identities, csr.URIs) {
		s.log.Errorf("failed to match URIs with identities: %v != %v",
			caller.Identities, csr.URIs)
		return identities, false
	}

	// return positive authn of given csr
	return identities, true
}

// identitiesMatch will ensure that two list of identities given from the
// request context, and those parsed from the CSR, match
func identitiesMatch(a []string, b []*url.URL) bool {
	if len(a) != len(b) {
		return false
	}

	aa := make([]string, len(a))
	bb := make([]*url.URL, len(b))

	copy(aa, a)
	copy(bb, b)

	sort.Strings(aa)
	sort.SliceStable(bb, func(i, j int) bool {
		return bb[i].String() < bb[j].String()
	})

	for i, v := range aa {
		if bb[i].String() != v {
			return false
		}
	}

	return true
}
