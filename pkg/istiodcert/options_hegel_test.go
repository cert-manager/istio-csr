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

package istiodcert

import (
	"strings"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"

	"hegel.dev/go/hegel"
)

// drawOptions draws an Options value covering valid and invalid
// combinations of every validated field.
func drawOptions(ht *hegel.T) Options {
	o := Options{
		Enabled:                 hegel.Draw(ht, hegel.Booleans()),
		Duration:                hegel.Draw(ht, hegel.SampledFrom([]time.Duration{30 * time.Minute, time.Hour})),
		RenewBefore:             hegel.Draw(ht, hegel.SampledFrom([]time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour})),
		KeyAlgorithm:            hegel.Draw(ht, hegel.SampledFrom([]string{"RSA", "rsa", "ECDSA", "ecdsa", "", "ED25519"})),
		KeySize:                 hegel.Draw(ht, hegel.SampledFrom([]int{-1, 0, 256, 384, 521, 1024, 2048, 4096})),
		MaxConcurrentReconciles: hegel.Draw(ht, hegel.Integers(-1, 3)),
	}
	dnsPool := []string{"example.com", "svc.cluster.local", "-bad.example.com", "UPPER.example.com"}
	for _, i := range hegel.Draw(ht, hegel.Lists(hegel.Integers(0, len(dnsPool)-1)).MaxSize(3)) {
		o.AdditionalDNSNames = append(o.AdditionalDNSNames, dnsPool[i])
	}
	return o
}

// optionsInvalid recomputes whether Validate must reject the options. The
// key size rules depend on the (normalized) algorithm: RSA accepts 0
// (defaulted) or anything >= 2048; ECDSA accepts 0 (defaulted), 256 or 384.
func optionsInvalid(o Options) bool {
	if o.MaxConcurrentReconciles < 1 || o.RenewBefore >= o.Duration {
		return true
	}
	switch strings.ToUpper(o.KeyAlgorithm) {
	case "RSA":
		if o.KeySize != 0 && o.KeySize < minRSAKeySize {
			return true
		}
	case "ECDSA":
		if o.KeySize != 0 && o.KeySize != 256 && o.KeySize != 384 {
			return true
		}
	default:
		return true
	}
	for _, name := range o.AdditionalDNSNames {
		if len(k8svalidation.IsDNS1123Subdomain(name)) > 0 {
			return true
		}
	}
	return false
}

// TestOptionsValidateProperties: Validate rejects exactly the invalid
// configurations, is a no-op when the istiod cert is disabled, normalizes
// accepted options (uppercased algorithm, defaulted key size, cert-manager
// algorithm set), and is idempotent.
//
// The error for an invalid additional DNS name currently quotes the
// validation errors where the name belongs and drops the name itself
// (options.go, "invalid additional DNS name %q: " fed with the joined
// validation errors); the property checks only that an error is returned.
func TestOptionsValidateProperties(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		o := drawOptions(ht)
		before := o
		err := o.Validate()

		if !before.Enabled {
			if err != nil {
				ht.Fatalf("disabled options rejected: %v", err)
			}
			// Disabled options are not normalized.
			if o.KeyAlgorithm != before.KeyAlgorithm || o.KeySize != before.KeySize {
				ht.Fatalf("disabled options mutated: %+v -> %+v", before, o)
			}
			return
		}

		if wantErr := optionsInvalid(before); (err != nil) != wantErr {
			ht.Fatalf("options %+v: error = %v, want error %t", before, err, wantErr)
		}

		if err == nil {
			switch o.KeyAlgorithm {
			case "RSA":
				if o.CMKeyAlgorithm != cmapi.RSAKeyAlgorithm || o.KeySize < minRSAKeySize {
					ht.Fatalf("accepted RSA options not normalized: %+v", o)
				}
			case "ECDSA":
				if o.CMKeyAlgorithm != cmapi.ECDSAKeyAlgorithm || (o.KeySize != 256 && o.KeySize != 384) {
					ht.Fatalf("accepted ECDSA options not normalized: %+v", o)
				}
			default:
				ht.Fatalf("accepted options with unnormalized algorithm %q", o.KeyAlgorithm)
			}
		}

		// Idempotence: validating the already-validated options changes
		// neither the outcome nor the options.
		again := o
		err2 := again.Validate()
		if (err2 != nil) != (err != nil) {
			ht.Fatalf("Validate not idempotent: first error %v, second error %v", err, err2)
		}
		if again.KeyAlgorithm != o.KeyAlgorithm || again.KeySize != o.KeySize || again.CMKeyAlgorithm != o.CMKeyAlgorithm {
			ht.Fatalf("second Validate mutated options: %+v -> %+v", o, again)
		}
	}, hegel.WithTestCases(1000))
}
