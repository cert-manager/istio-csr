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

package extensions

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	pkiutil "github.com/cert-manager/cert-manager/pkg/util/pki"
)

var (
	disallowedX509KeyUsages = []any{
		x509.KeyUsageContentCommitment,
		x509.KeyUsageDataEncipherment,
		x509.KeyUsageKeyAgreement,
		x509.KeyUsageCertSign,
		x509.KeyUsageCRLSign,
		x509.KeyUsageEncipherOnly,
		x509.KeyUsageDecipherOnly,
	}

	allowedX509KeyUsages = []any{
		x509.KeyUsageDigitalSignature,
		x509.KeyUsageKeyEncipherment,
	}

	disallowedX509ExtKeyUsages = []any{
		x509.ExtKeyUsageAny,
		x509.ExtKeyUsageCodeSigning,
		x509.ExtKeyUsageEmailProtection,
		x509.ExtKeyUsageIPSECEndSystem,
		x509.ExtKeyUsageIPSECTunnel,
		x509.ExtKeyUsageIPSECUser,
		x509.ExtKeyUsageTimeStamping,
		x509.ExtKeyUsageOCSPSigning,
		x509.ExtKeyUsageMicrosoftServerGatedCrypto,
		x509.ExtKeyUsageNetscapeServerGatedCrypto,
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
		x509.ExtKeyUsageMicrosoftKernelCodeSigning,
	}

	allowedX509ExtKeyUsages = []any{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
	}
)

func TestValidateCSRExtentions(t *testing.T) {
	sk, err := pkiutil.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		emails []string
		dns    []string
		uris   []string
		ips    []string
		usages []cmapi.KeyUsage
		expErr bool
	}{
		"if single URI name exists, shouldn't error": {
			uris:   []string{"spiffe://foo.bar"},
			expErr: false,
		},
		"if single URI name exist with allowed usages, shouldn't error": {
			uris: []string{"spiffe://foo.bar"},
			usages: []cmapi.KeyUsage{
				cmapi.UsageDigitalSignature,
				cmapi.UsageKeyEncipherment,
				cmapi.UsageClientAuth,
				cmapi.UsageServerAuth,
			},
			expErr: false,
		},
		"if multiple URI names exist with allowed usages, shouldn't error": {
			uris: []string{"spiffe://foo.bar", "spiffe://bar.foo"},
			usages: []cmapi.KeyUsage{
				cmapi.UsageDigitalSignature,
				cmapi.UsageKeyEncipherment,
				cmapi.UsageClientAuth,
				cmapi.UsageServerAuth,
			},
			expErr: false,
		},
		"if multiple URI names exist, dns name, and allowed usages, should error": {
			uris: []string{"spiffe://foo.bar", "spiffe://bar.foo"},
			dns:  []string{"foo.bar"},
			usages: []cmapi.KeyUsage{
				cmapi.UsageDigitalSignature,
				cmapi.UsageKeyEncipherment,
				cmapi.UsageClientAuth,
				cmapi.UsageServerAuth,
			},
			expErr: true,
		},
		"if multiple URI names exist, ips, and allowed usages, should error": {
			uris: []string{"spiffe://foo.bar", "spiffe://bar.foo"},
			ips:  []string{"1.2.3.4"},
			usages: []cmapi.KeyUsage{
				cmapi.UsageDigitalSignature,
				cmapi.UsageKeyEncipherment,
				cmapi.UsageClientAuth,
				cmapi.UsageServerAuth,
			},
			expErr: true,
		},
		"if multiple URI names exist, emails, and allowed usages, should error": {
			uris:   []string{"spiffe://foo.bar", "spiffe://bar.foo"},
			emails: []string{"hello@example.com"},
			usages: []cmapi.KeyUsage{
				cmapi.UsageDigitalSignature,
				cmapi.UsageKeyEncipherment,
				cmapi.UsageClientAuth,
				cmapi.UsageServerAuth,
			},
			expErr: true,
		},
		"if multiple URI names exist, emails, dns, ips, and allowed usages, should error": {
			uris:   []string{"spiffe://foo.bar", "spiffe://bar.foo"},
			dns:    []string{"foo.bar"},
			ips:    []string{"1.2.3.4"},
			emails: []string{"hello@example.com"},
			usages: []cmapi.KeyUsage{
				cmapi.UsageDigitalSignature,
				cmapi.UsageKeyEncipherment,
				cmapi.UsageClientAuth,
				cmapi.UsageServerAuth,
			},
			expErr: true,
		},
		"if multiple URI names exist, and subset allowed usages, shouldn't error": {
			uris: []string{"spiffe://foo.bar", "spiffe://bar.foo"},
			usages: []cmapi.KeyUsage{
				cmapi.UsageDigitalSignature,
				cmapi.UsageServerAuth,
			},
			expErr: false,
		},
		"if multiple URI names exist, with disallowed usages, should error": {
			uris: []string{"spiffe://foo.bar", "spiffe://bar.foo"},
			usages: []cmapi.KeyUsage{
				cmapi.UsageDigitalSignature,
				cmapi.UsageKeyEncipherment,
				cmapi.UsageClientAuth,
				cmapi.UsageServerAuth,
				cmapi.UsageCertSign,
			},
			expErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			csr, err := pkiutil.GenerateCSR(&cmapi.Certificate{
				Spec: cmapi.CertificateSpec{
					EmailAddresses: test.emails,
					DNSNames:       test.dns,
					IPAddresses:    test.ips,
					Usages:         test.usages,
					URIs:           test.uris,
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			// Re encode/parse csr to simulate real x509 csr parsing
			csrDER, err := pkiutil.EncodeCSR(csr, sk)
			if err != nil {
				t.Fatal(err)
			}

			csr, err = x509.ParseCertificateRequest(csrDER)
			if err != nil {
				t.Fatal(err)
			}

			err = ValidateCSRExtentions(csr)
			if (err != nil) != test.expErr {
				t.Errorf("unexpected error, exp=%t got=%v",
					test.expErr, err)
			}
		})
	}
}

func TestValidateExtendedKeyUsageExtension(t *testing.T) {
	type testcase struct {
		usages []x509.ExtKeyUsage
		expErr bool
	}

	var (
		tests []testcase
		// Generate powerset of both disallowed and allowed usages
		disallowedExtUsagesPowerset = powerset(disallowedX509ExtKeyUsages)
		allowedExtUsagesPowerset    = append(powerset(allowedX509ExtKeyUsages), nil)
	)

	// Expect all sets with any disallowed usages to always fail
	for _, disallowed := range disallowedExtUsagesPowerset {
		for _, allowed := range allowedExtUsagesPowerset {
			var extUsages []x509.ExtKeyUsage
			for _, usage := range append(disallowed, allowed...) {
				extUsages = append(extUsages, usage.(x509.ExtKeyUsage))
			}

			tests = append(tests, testcase{extUsages, true})
		}
	}

	for _, allowed := range allowedExtUsagesPowerset {
		var extUsages []x509.ExtKeyUsage
		for _, usage := range allowed {
			extUsages = append(extUsages, usage.(x509.ExtKeyUsage))
		}

		tests = append(tests, testcase{extUsages, true})
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("ext usages [%v] expErr=%t", test.usages, test.expErr), func(t *testing.T) {
			var ids []asn1.ObjectIdentifier
			for _, usage := range test.usages {
				id, ok := pkiutil.OIDFromExtKeyUsage(usage)
				if !ok {
					t.Fatalf("%v", usage)
				}

				ids = append(ids, id)
			}

			val, err := asn1.Marshal(ids)
			if err != nil {
				t.Fatal(err)
			}

			extension := pkix.Extension{
				Id:    oidExtensionKeyUsage,
				Value: val,
			}

			err = validateExtendedKeyUsageExtension(extension)
			if (err != nil) != test.expErr {
				t.Errorf("unexpected error, exp=%t got=%v (%v)", test.expErr, err, test.usages)
			}
		})
	}
}

func TestValidateKeyUsageExtension(t *testing.T) {
	type testcase struct {
		usage  x509.KeyUsage
		expErr bool
	}

	var (
		tests []testcase
		// Generate powerset of both disallowed and allowed usages
		disallowedUsagesPowerset = powerset(disallowedX509KeyUsages)
		allowedUsagesPowerset    = append(powerset(allowedX509KeyUsages), nil)
	)

	// Expect all sets with any disallowed usages to always fail
	for _, disallowed := range disallowedUsagesPowerset {
		for _, allowed := range allowedUsagesPowerset {
			var ku x509.KeyUsage
			for _, use := range append(disallowed, allowed...) {
				ku |= use.(x509.KeyUsage)
			}

			tests = append(tests, testcase{ku, true})
		}
	}

	// Expect all sets with only allowed or empty usages to always pass
	for _, allowed := range allowedUsagesPowerset {
		var ku x509.KeyUsage
		for _, use := range allowed {
			ku |= use.(x509.KeyUsage)
		}

		tests = append(tests, testcase{ku, false})
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("usage [%v] expErr=%t", test.usage, test.expErr), func(t *testing.T) {
			ext, err := buildASN1KeyUsageRequest(test.usage)
			if err != nil {
				t.Fatal(err)
			}

			err = validateKeyUsageExtension(ext.Value)
			if (err != nil) != test.expErr {
				t.Errorf("unexpected error, exp=%t got=%v (%v)", test.expErr, err, test.usage)
			}
		})
	}
}

// Adapted from https://github.com/mxschmitt/golang-combinations
func powerset(set []any) (subsets [][]any) {
	length := uint(len(set))

	// Go through all possible combinations of objects
	// from 1 (only first object in subset) to 2^length (all objects in subset)
	for subsetBits := 1; subsetBits < (1 << length); subsetBits++ {
		var subset []any

		for object := range length {
			// checks if object is contained in subset
			// by checking if bit 'object' is set in subsetBits
			if (subsetBits>>object)&1 == 1 {
				// add object to subset
				subset = append(subset, set[object])
			}
		}
		// add subset to subsets
		subsets = append(subsets, subset)
	}

	return subsets
}

// Copied from x509.go
func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

// Adapted from x509.go
func buildASN1KeyUsageRequest(usage x509.KeyUsage) (pkix.Extension, error) {
	OIDExtensionKeyUsage := pkix.Extension{
		Id: oidExtensionKeyUsage,
	}
	var a [2]byte
	a[0] = reverseBitsInAByte(byte(usage & 0xff))
	a[1] = reverseBitsInAByte(byte((usage >> 8) & 0xff))

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bitString := a[:l]
	var err error
	OIDExtensionKeyUsage.Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
	if err != nil {
		return pkix.Extension{}, err
	}

	return OIDExtensionKeyUsage, nil
}

// asn1BitLength returns the bit-length of bitString by considering the
// most-significant bit in a byte to be the "first" bit. This convention
// matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := range uint(8) {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}
