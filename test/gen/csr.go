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

package gen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/url"

	pkiutil "istio.io/istio/security/pkg/pki/util"
)

type CSRBuilder struct {
	ids, dns, ips, emails []string
	cn                    string
}

type CSRModifier func(*CSRBuilder)

func CSR(mods ...CSRModifier) ([]byte, error) {
	csrBuilder := new(CSRBuilder)

	for _, mod := range mods {
		mod(csrBuilder)
	}

	opts := pkiutil.CertOptions{
		IsServer:   true,
		RSAKeySize: 2048,
	}

	csr, err := pkiutil.GenCSRTemplate(opts)
	if err != nil {
		return nil, err
	}

	for _, id := range csrBuilder.ids {
		url, err := url.Parse(id)
		if err != nil {
			return nil, err
		}

		csr.URIs = append(csr.URIs, url)
	}

	for _, ip := range csrBuilder.ips {
		csr.IPAddresses = append(csr.IPAddresses, net.ParseIP(ip))
	}

	csr.DNSNames = csrBuilder.dns
	csr.EmailAddresses = csrBuilder.emails
	csr.Subject.CommonName = csrBuilder.cn

	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, sk)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}), nil
}

func SetCSRIdentities(ids []string) CSRModifier {
	return func(csr *CSRBuilder) {
		csr.ids = ids
	}
}

func SetCSRDNS(dns []string) CSRModifier {
	return func(csr *CSRBuilder) {
		csr.dns = dns
	}
}

func SetCSRIPs(ips []string) CSRModifier {
	return func(csr *CSRBuilder) {
		csr.ips = ips
	}
}

func SetCSREmails(emails []string) CSRModifier {
	return func(csr *CSRBuilder) {
		csr.emails = emails
	}
}

func SetCSRCommonName(cn string) CSRModifier {
	return func(csr *CSRBuilder) {
		csr.cn = cn
	}
}
