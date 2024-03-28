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
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
)

const (
	// Mapping from the type of an identity to the OID tag value for the X.509
	// SAN field (see https://tools.ietf.org/html/rfc5280#appendix-A.2)
	//
	// SubjectAltName ::= GeneralNames
	//
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      uniformResourceIdentifier       [6]     IA5String,
	// }
	asn1TagURI = 6
)

var (
	// Copied from https://github.com/golang/go/blob/dev.boringcrypto.go1.16/src/crypto/x509/x509.go
	oidExtensionKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtensionSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}

	oidExtKeyUsageServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}

	allowedKeyUsages = [][]byte{
		{3, 2, 7, 128}, // x509.KeyUsageDigitalSignature
		{3, 2, 5, 32},  // x509.KeyUsageKeyEncipherment
	}
)

// ValidateCSRExtentions validates the given certificate signing request
// contains only valid extensions, including URI sans, key usages, and extended
// key usages. Any other extensions will error.
func ValidateCSRExtentions(csr *x509.CertificateRequest) error {
	var el []error

	if len(csr.ExtraExtensions) > 0 {
		el = append(el, fmt.Errorf("forbidden extensions: %v", csr.Extensions))
	}

	for _, extension := range csr.Extensions {
		switch {
		case extension.Id.Equal(oidExtensionSubjectAltName):
			el = append(el, validateSubjectAltNameExtension(extension))

		case extension.Id.Equal(oidExtensionKeyUsage):
			el = append(el, validateKeyUsageExtension(extension.Value))

		case extension.Id.Equal(oidExtensionExtendedKeyUsage):
			el = append(el, validateExtendedKeyUsageExtension(extension))

		default:
			el = append(el, fmt.Errorf("forbidden extension: %s", extension.Id))
		}
	}

	return utilerrors.NewAggregate(el)
}

// validateKeyUsageExtension validates that the passed extension value contains
// accepted key usages
func validateKeyUsageExtension(value []byte) error {
	if len(value) != 4 {
		return fmt.Errorf("forbidden key usage: %v", value)
	}

	extValue := make([]byte, len(value))
	copy(extValue, value)

	// Clear allowed usages bits from value
	for _, usage := range allowedKeyUsages {
		for i, b := range usage {
			extValue[i] &^= b
		}
	}

	// If usage bits are not empty, forbidden usages used
	if !bytes.Equal(extValue, []byte{0, 0, 0, 0}) {
		return fmt.Errorf("forbidden key usage: %v", value)
	}

	return nil
}

// validateExtendedKeyUsageExtension validates that the passed extension
// contains accepted extended key usages
func validateExtendedKeyUsageExtension(extension pkix.Extension) error {
	if !extension.Id.Equal(oidExtensionExtendedKeyUsage) {
		return fmt.Errorf("non extended key usage extension: %s", extension.Id)
	}

	var asn1ExtendedUsages []asn1.ObjectIdentifier
	_, err := asn1.Unmarshal(extension.Value, &asn1ExtendedUsages)
	if err != nil {
		return fmt.Errorf("failed to parse extended key usages: %s", err)
	}

	var el []error
	for _, usage := range asn1ExtendedUsages {
		if !usage.Equal(oidExtKeyUsageClientAuth) && !usage.Equal(oidExtKeyUsageServerAuth) {
			el = append(el, fmt.Errorf("forbidden extended key usage: %s", usage))
		}
	}

	return utilerrors.NewAggregate(el)
}

// validateSubjectAltNameExtension validates that the passed extension is a
// correctly encoded URI SAN, and is no other SAN type
func validateSubjectAltNameExtension(ext pkix.Extension) error {
	if !ext.Id.Equal(oidExtensionSubjectAltName) {
		return fmt.Errorf("extension is not a SAN type: %s", ext.Id)
	}

	var sequence asn1.RawValue
	if rest, err := asn1.Unmarshal(ext.Value, &sequence); err != nil {
		return fmt.Errorf("failed to unmarshal san extension: %v", err)
	} else if len(rest) != 0 {
		return fmt.Errorf("san extension incorrectly encoded: %v", ext.Value)
	}

	// Check the rawValue is a sequence.
	if !sequence.IsCompound || sequence.Tag != asn1.TagSequence || sequence.Class != asn1.ClassUniversal {
		return fmt.Errorf("san extension is incorrectly encoded: %v", ext.Value)
	}

	for bytes := sequence.Bytes; len(bytes) > 0; {
		var (
			rawValue asn1.RawValue
			err      error
		)

		bytes, err = asn1.Unmarshal(bytes, &rawValue)
		if err != nil {
			return err
		}

		// Only URI SANs are permitted for istio certificates
		if rawValue.Tag != asn1TagURI {
			return fmt.Errorf("non uri san extension given: %s", rawValue.Bytes)
		}
	}

	return nil
}
