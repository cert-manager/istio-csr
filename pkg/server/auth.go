package server

import (
	"context"
	"fmt"
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
		s.log.Error(err, "failed to authenticate request")
		return "", false
	}

	// request authentication has no identities, so error
	if len(caller.Identities) == 0 {
		s.log.Error(fmt.Errorf("%s", caller.Identities), "request sent with no identity")
		return "", false
	}

	// return concatenated list of verified ids
	identities := strings.Join(caller.Identities, ",")

	csr, err := pkiutil.ParsePemEncodedCSR(csrPEM)
	if err != nil {
		s.log.Error(err, "failed to decode CSR from %s")
		return identities, false
	}

	// if the csr contains any other options set, error
	if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 ||
		len(csr.Subject.CommonName) > 0 || len(csr.EmailAddresses) > 0 {
		msg := fmt.Sprintf("DNS=%v IPs=%v CN=%s EMAIL=%v",
			csr.DNSNames, csr.IPAddresses,
			csr.Subject.CommonName, csr.EmailAddresses)

		s.log.Error(fmt.Errorf("bad request from %s", identities), msg)

		return identities, false
	}

	// ensure identity matches requests URIs
	if !identitiesMatch(caller.Identities, csr.URIs) {
		s.log.Error(fmt.Errorf("%v != %v", caller.Identities, csr.URIs), "failed to match URIs with identities")
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
