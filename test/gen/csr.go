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
