/*
Copyright 2026 The cert-manager Authors.

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
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	pkiutil "github.com/cert-manager/cert-manager/pkg/util/pki"

	"hegel.dev/go/hegel"
)

// The complete x509.KeyUsage space is 9 bits, KeyUsageDigitalSignature (1<<0)
// through KeyUsageDecipherOnly (1<<8).
const maxKeyUsage = int(x509.KeyUsageDecipherOnly)<<1 - 1

// TestValidateKeyUsageExtensionProperty: for every possible key usage bit
// combination, encoded exactly as crypto/x509 encodes it in a CSR, the
// extension is accepted iff it contains no bits beyond digitalSignature and
// keyEncipherment. Replaces the powerset-enumeration table, which covered the
// same space.
func TestValidateKeyUsageExtensionProperty(t *testing.T) {
	allowed := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment

	hegel.Test(t, func(ht *hegel.T) {
		usage := x509.KeyUsage(hegel.Draw(ht, hegel.Integers(0, maxKeyUsage)))

		ext, err := buildASN1KeyUsageRequest(usage)
		if err != nil {
			ht.Fatalf("failed to encode key usage %v: %v", usage, err)
		}

		err = validateKeyUsageExtension(ext.Value)
		if wantErr := usage&^allowed != 0; (err != nil) != wantErr {
			ht.Fatalf("usage %b: error = %v, want error %t", usage, err, wantErr)
		}
	}, hegel.WithTestCases(1000))
}

// extKeyUsages is the draw pool for extended key usages: the two allowed ones
// followed by a sample of forbidden ones. Order matters for deterministic
// draws.
var extKeyUsages = []struct {
	usage   x509.ExtKeyUsage
	allowed bool
}{
	{x509.ExtKeyUsageServerAuth, true},
	{x509.ExtKeyUsageClientAuth, true},
	{x509.ExtKeyUsageAny, false},
	{x509.ExtKeyUsageCodeSigning, false},
	{x509.ExtKeyUsageEmailProtection, false},
	{x509.ExtKeyUsageIPSECEndSystem, false},
	{x509.ExtKeyUsageIPSECTunnel, false},
	{x509.ExtKeyUsageIPSECUser, false},
	{x509.ExtKeyUsageTimeStamping, false},
	{x509.ExtKeyUsageOCSPSigning, false},
	{x509.ExtKeyUsageMicrosoftServerGatedCrypto, false},
	{x509.ExtKeyUsageNetscapeServerGatedCrypto, false},
	{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, false},
	{x509.ExtKeyUsageMicrosoftKernelCodeSigning, false},
}

// TestValidateExtendedKeyUsageExtensionProperty: an extended key usage
// extension is accepted iff every OID in it is serverAuth or clientAuth, and
// an extension with any other OID as its extension ID is always rejected.
//
// The table test this replaces built every extension with the plain key usage
// OID as the extension ID, so validateExtendedKeyUsageExtension rejected all
// of its cases at the ID check and the usage loop was never reached; that is
// why even its allowed-only rows asserted an error.
func TestValidateExtendedKeyUsageExtensionProperty(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		var ids []asn1.ObjectIdentifier
		anyForbidden := false
		for _, i := range hegel.Draw(ht, hegel.Lists(hegel.Integers(0, len(extKeyUsages)-1)).MaxSize(5)) {
			id, ok := pkiutil.OIDFromExtKeyUsage(extKeyUsages[i].usage)
			if !ok {
				ht.Fatalf("no OID for %v", extKeyUsages[i].usage)
			}
			ids = append(ids, id)
			anyForbidden = anyForbidden || !extKeyUsages[i].allowed
		}

		val, err := asn1.Marshal(ids)
		if err != nil {
			ht.Fatalf("failed to marshal OIDs: %v", err)
		}

		err = validateExtendedKeyUsageExtension(pkix.Extension{Id: oidExtensionExtendedKeyUsage, Value: val})
		if (err != nil) != anyForbidden {
			ht.Fatalf("usages %v: error = %v, want error %t", ids, err, anyForbidden)
		}

		// The same value under a different extension ID is never an extended
		// key usage extension.
		if err := validateExtendedKeyUsageExtension(pkix.Extension{Id: oidExtensionKeyUsage, Value: val}); err == nil {
			ht.Fatalf("extension with non-EKU ID accepted")
		}
	}, hegel.WithTestCases(1000))
}

// csrKeyUsages is the draw pool for cert-manager key usages requested in a
// CSR: the four allowed ones followed by a sample of forbidden ones.
var csrKeyUsages = []struct {
	usage   cmapi.KeyUsage
	allowed bool
}{
	{cmapi.UsageDigitalSignature, true},
	{cmapi.UsageKeyEncipherment, true},
	{cmapi.UsageClientAuth, true},
	{cmapi.UsageServerAuth, true},
	{cmapi.UsageAny, false},
	{cmapi.UsageContentCommitment, false},
	{cmapi.UsageDataEncipherment, false},
	{cmapi.UsageKeyAgreement, false},
	{cmapi.UsageCertSign, false},
	{cmapi.UsageCRLSign, false},
	{cmapi.UsageCodeSigning, false},
	{cmapi.UsageEmailProtection, false},
	{cmapi.UsageTimestamping, false},
	{cmapi.UsageOCSPSigning, false},
}

// TestValidateCSRExtentionsProperties: a real CSR, generated and encoded with
// the same cert-manager helpers istio agents' requests are checked against,
// passes validation iff it carries only URI SANs and only allowed (extended)
// key usages. Any DNS name, IP address or email SAN, or any forbidden usage,
// rejects the CSR. Replaces the example table, whose rows instantiated the
// same rule.
func TestValidateCSRExtentionsProperties(t *testing.T) {
	sk, err := pkiutil.GenerateECPrivateKey(256)
	if err != nil {
		t.Fatal(err)
	}

	uriPool := []string{"spiffe://foo.bar", "spiffe://bar.foo", "spiffe://cluster.local/ns/a/sa/b"}
	dnsPool := []string{"example.com", "foo.bar"}
	ipPool := []string{"1.2.3.4", "2001:db8::1"}
	emailPool := []string{"hello@example.com"}

	drawSubset := func(ht *hegel.T, pool []string, maxSize int) []string {
		var out []string
		for _, i := range hegel.Draw(ht, hegel.Lists(hegel.Integers(0, len(pool)-1)).MaxSize(maxSize)) {
			out = append(out, pool[i])
		}
		return out
	}

	hegel.Test(t, func(ht *hegel.T) {
		spec := cmapi.CertificateSpec{
			PrivateKey:     &cmapi.CertificatePrivateKey{Algorithm: cmapi.ECDSAKeyAlgorithm},
			DNSNames:       drawSubset(ht, dnsPool, 2),
			IPAddresses:    drawSubset(ht, ipPool, 2),
			EmailAddresses: drawSubset(ht, emailPool, 1),
		}
		// Always include at least one URI, as every istio agent CSR does.
		spec.URIs = append([]string{uriPool[hegel.Draw(ht, hegel.Integers(0, len(uriPool)-1))]}, drawSubset(ht, uriPool, 2)...)

		anyForbiddenUsage := false
		for _, i := range hegel.Draw(ht, hegel.Lists(hegel.Integers(0, len(csrKeyUsages)-1)).MaxSize(5)) {
			spec.Usages = append(spec.Usages, csrKeyUsages[i].usage)
			anyForbiddenUsage = anyForbiddenUsage || !csrKeyUsages[i].allowed
		}

		csr, err := pkiutil.GenerateCSR(&cmapi.Certificate{Spec: spec})
		if err != nil {
			ht.Fatalf("failed to generate CSR: %v", err)
		}
		csrDER, err := pkiutil.EncodeCSR(csr, sk)
		if err != nil {
			ht.Fatalf("failed to encode CSR: %v", err)
		}
		csr, err = x509.ParseCertificateRequest(csrDER)
		if err != nil {
			ht.Fatalf("failed to parse CSR: %v", err)
		}

		wantErr := len(spec.DNSNames) > 0 || len(spec.IPAddresses) > 0 || len(spec.EmailAddresses) > 0 || anyForbiddenUsage
		if err := ValidateCSRExtentions(csr); (err != nil) != wantErr {
			ht.Fatalf("spec %+v: error = %v, want error %t", spec, err, wantErr)
		}
	}, hegel.WithTestCases(250))
}

// TestValidateCSRExtentionsArbitraryBytes: validation must never panic, and
// never accept, a SAN extension carrying arbitrary bytes, an unknown
// extension, or a CSR with ExtraExtensions set.
func TestValidateCSRExtentionsArbitraryBytes(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		ext := pkix.Extension{Value: hegel.Draw(ht, hegel.Binary(0, 100))}
		field := &x509.CertificateRequest{}
		switch hegel.Draw(ht, hegel.Integers(0, 2)) {
		case 0:
			// Arbitrary bytes are never a valid URI-SAN-only extension: a
			// valid one is a compound ASN.1 sequence of tagged general names,
			// which these draw sizes cannot produce by chance.
			ext.Id = oidExtensionSubjectAltName
			field.Extensions = []pkix.Extension{ext}
		case 1:
			ext.Id = asn1.ObjectIdentifier{1, 2, 3, 4}
			field.Extensions = []pkix.Extension{ext}
		case 2:
			ext.Id = oidExtensionSubjectAltName
			field.ExtraExtensions = []pkix.Extension{ext}
		}
		if err := ValidateCSRExtentions(field); err == nil {
			ht.Fatalf("invalid extension accepted: %+v", field)
		}
	}, hegel.WithTestCases(1000))
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
