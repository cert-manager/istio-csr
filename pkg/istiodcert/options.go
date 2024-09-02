/*
Copyright 2024 The cert-manager Authors.

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

package istiodcert

import (
	"errors"
	"fmt"
	"strings"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/spf13/pflag"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
)

const (
	// minRSAKeySize is the minimum allowed RSA key size for the istiod certificate
	minRSAKeySize int = 2048
)

// Options holds various configuration options for generating the istiod certificate
type Options struct {
	Enabled bool

	CertificateName      string
	CertificateNamespace string

	Duration    time.Duration
	RenewBefore time.Duration

	KeyAlgorithm string
	KeySize      int

	CMKeyAlgorithm cmapi.PrivateKeyAlgorithm

	AdditionalDNSNames    []string
	AdditionalAnnotations map[string]string

	IstioRevisions []string
}

// Validate confirms that the given istiod cert options are valid
func (o *Options) Validate() error {
	// no point in validating if the config won't be used
	if !o.Enabled {
		return nil
	}

	var errs []error

	if o.RenewBefore.Nanoseconds() >= o.Duration.Nanoseconds() {
		errs = append(errs, fmt.Errorf("istiod certificate renew-before %s must be smaller than the requested duration %s", o.RenewBefore.String(), o.Duration.String()))
	}

	o.KeyAlgorithm = strings.ToUpper(o.KeyAlgorithm)

	switch o.KeyAlgorithm {
	case "RSA":
		o.CMKeyAlgorithm = cmapi.RSAKeyAlgorithm

		if o.KeySize == 0 {
			o.KeySize = minRSAKeySize
		}

		if o.KeySize < minRSAKeySize {
			errs = append(errs, fmt.Errorf("istio certificate RSA key size must be at least %d bits, but got %d", minRSAKeySize, o.KeySize))
		}

	case "ECDSA":
		o.CMKeyAlgorithm = cmapi.ECDSAKeyAlgorithm

		if o.KeySize == 0 {
			o.KeySize = 256
		}

		if o.KeySize != 256 && o.KeySize != 384 {
			errs = append(errs, fmt.Errorf("istio certificate private key of type ECDSA must have 'size' equal to either 256 or 384"))
		}

	default:
		errs = append(errs, fmt.Errorf("invalid key algorithm %q; valid values are RSA and ECDSA", o.KeyAlgorithm))
	}

	if len(o.AdditionalDNSNames) > 0 {
		for _, name := range o.AdditionalDNSNames {
			// IsDNS1123Subdomain is equivalent to "IsValidDNSName"
			// This validation function returns a slice of strings if there was an error
			validationErrors := k8svalidation.IsDNS1123Subdomain(name)
			if len(validationErrors) > 0 {
				errs = append(errs, fmt.Errorf("invalid additional DNS name %q: ", strings.Join(validationErrors, ", ")))
			}
		}
	}

	return errors.Join(errs...)
}

func AddFlags(o *Options, fs *pflag.FlagSet) {
	fs.BoolVar(&o.Enabled, "istiod-cert-enabled", false, "Whether to dynamically provision the istiod certificate")

	fs.StringVar(&o.CertificateName, "istiod-cert-name", "istiod-dynamic", "Name of the Certificate resource to use for dynamic istiod provisioning")

	fs.StringVar(&o.CertificateNamespace, "istiod-cert-namespace", "istio-system", "Namespace for the dynamic istiod cert")

	fs.DurationVar(&o.Duration, "istiod-cert-duration", time.Hour,
		"Requested duration of the istiod certificate, if enabled")

	fs.DurationVar(&o.RenewBefore, "istiod-cert-renew-before", 30*time.Minute,
		"How long to wait before trying to renew the istiod certificate (if enabled). Must be less than duration.")

	fs.StringVar(&o.KeyAlgorithm, "istiod-cert-key-algorithm", "RSA", "Key algorithm to use for the istiod cert. Can be RSA or ECDSA.")

	fs.IntVar(&o.KeySize, "istiod-cert-key-size", minRSAKeySize,
		fmt.Sprintf("Parameter for istiod certificate key. For RSA, must be a number of bits >= %d. For ECDSA, can only be 256 or 384, corresponding to P-256 and P-384 respectively.", minRSAKeySize))

	fs.StringSliceVar(&o.AdditionalDNSNames, "istiod-cert-additional-dns-names", []string{}, "Additional DNS names to use for istiod cert (if enabled). Useful if istiod needs to be accessible outside of the cluster")

	fs.StringToStringVar(&o.AdditionalAnnotations, "istiod-cert-additional-annotations", map[string]string{}, "Additional annotations to add for the istiod cert (if enabled).")

	fs.StringSliceVar(&o.IstioRevisions, "istiod-cert-istio-revisions", []string{}, "A list of istio revisions which should have DNS SAN entries in the dynamic istiod cert")
}
