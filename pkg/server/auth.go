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
	"fmt"
	"net/url"
	"sort"
	"strings"

	pkiutil "istio.io/istio/security/pkg/pki/util"

	"github.com/cert-manager/istio-csr/pkg/server/internal/extensions"
)

// authRequest will authenticate the request and authorize the CSR is valid for
// the identity
func (s *Server) authRequest(ctx context.Context, csrPEM []byte) (string, bool) {
	caller, err := s.opts.Auther.Authenticate(ctx)
	if err != nil {
		// TODO: pass in logger with request context
		s.log.Error(err, "failed to authenticate request")
		return "", false
	}

	// request authentication has no identities, so error
	if len(caller.Identities) == 0 {
		s.log.Error(errors.New("request sent with no identity"), "")
		return "", false
	}

	// return concatenated list of verified ids
	identities := strings.Join(caller.Identities, ",")
	log := s.log.WithValues("identities", identities)

	csr, err := pkiutil.ParsePemEncodedCSR(csrPEM)
	if err != nil {
		log.Error(err, "failed to decode CSR")
		return identities, false
	}

	if err := csr.CheckSignature(); err != nil {
		log.Error(err, "CSR failed signature check")
		return identities, false
	}

	// if the csr contains any other options set, error
	if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 ||
		len(csr.Subject.CommonName) > 0 || len(csr.EmailAddresses) > 0 {
		log.Error(errors.New("forbidden extensions"), "",
			"dns", csr.DNSNames,
			"ips", csr.IPAddresses,
			"common-name", csr.Subject.CommonName,
			"emails", csr.EmailAddresses)

		return identities, false
	}

	// ensure csr extensions are valid
	if err := extensions.ValidateCSRExtentions(csr); err != nil {
		log.Error(err, "forbidden extensions")
		return identities, false
	}

	// ensure identity matches requests URIs
	if !identitiesMatch(caller.Identities, csr.URIs) {
		log.Error(fmt.Errorf("%v != %v", caller.Identities, csr.URIs), "failed to match URIs with identities")
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
