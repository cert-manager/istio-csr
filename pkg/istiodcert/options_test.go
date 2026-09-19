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
	"strings"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// validOptions returns options which Validate accepts, so each test case only
// has to state the field it is exercising.
func validOptions() Options {
	return Options{
		Enabled:                 true,
		Duration:                time.Hour,
		RenewBefore:             30 * time.Minute,
		KeyAlgorithm:            "RSA",
		KeySize:                 minRSAKeySize,
		MaxConcurrentReconciles: 1,
	}
}

func TestOptionsValidate(t *testing.T) {
	tests := map[string]struct {
		mutate      func(*Options)
		expErr      bool
		expContains []string
	}{
		"valid options are accepted": {
			mutate: func(*Options) {},
		},
		"a disabled config is not validated at all": {
			mutate: func(o *Options) {
				o.Enabled = false
				o.KeyAlgorithm = "not-a-real-algorithm"
				o.MaxConcurrentReconciles = 0
			},
		},
		"max-concurrent-reconciles below 1 is rejected": {
			mutate:      func(o *Options) { o.MaxConcurrentReconciles = 0 },
			expErr:      true,
			expContains: []string{"max-concurrent-reconciles must be at least 1, got 0"},
		},
		"renew-before equal to the duration is rejected": {
			mutate:      func(o *Options) { o.RenewBefore = o.Duration },
			expErr:      true,
			expContains: []string{"renew-before"},
		},
		"an RSA key below the minimum size is rejected": {
			mutate:      func(o *Options) { o.KeySize = minRSAKeySize - 1 },
			expErr:      true,
			expContains: []string{"at least 2048 bits"},
		},
		"an unknown key algorithm is rejected": {
			mutate:      func(o *Options) { o.KeyAlgorithm = "ed25519" },
			expErr:      true,
			expContains: []string{`invalid key algorithm "ED25519"`},
		},
		"an ECDSA key of an unsupported size is rejected": {
			mutate: func(o *Options) {
				o.KeyAlgorithm = "ECDSA"
				o.KeySize = 521
			},
			expErr:      true,
			expContains: []string{"256 or 384"},
		},
		// The offending name is what the operator has to go and correct, so it
		// has to survive into the message.
		"an invalid additional DNS name is reported with the name and the reason": {
			mutate:      func(o *Options) { o.AdditionalDNSNames = []string{"NOT_A_DNS_NAME"} },
			expErr:      true,
			expContains: []string{`invalid additional DNS name "NOT_A_DNS_NAME"`, "lower case alphanumeric"},
		},
		"every invalid additional DNS name is reported": {
			mutate: func(o *Options) {
				o.AdditionalDNSNames = []string{"valid.example.com", "Bad.One", "worse_one"}
			},
			expErr:      true,
			expContains: []string{`"Bad.One"`, `"worse_one"`},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			o := validOptions()
			test.mutate(&o)

			err := o.Validate()
			if !test.expErr {
				if err != nil {
					t.Fatalf("expected no error but got: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("expected an error but got nil")
			}

			for _, want := range test.expContains {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("expected the error to mention %q, but got: %v", want, err)
				}
			}
		})
	}
}

// Validate fills in the defaults it documents through the flags, so those are
// behaviour rather than an implementation detail.
func TestOptionsValidateDefaults(t *testing.T) {
	tests := map[string]struct {
		algorithm    string
		expKeySize   int
		expCMKeyAlgo cmapi.PrivateKeyAlgorithm
	}{
		"RSA defaults to the minimum key size": {
			algorithm:    "rsa",
			expKeySize:   minRSAKeySize,
			expCMKeyAlgo: cmapi.RSAKeyAlgorithm,
		},
		"ECDSA defaults to 256": {
			algorithm:    "ecdsa",
			expKeySize:   256,
			expCMKeyAlgo: cmapi.ECDSAKeyAlgorithm,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			o := validOptions()
			o.KeyAlgorithm = test.algorithm
			o.KeySize = 0

			if err := o.Validate(); err != nil {
				t.Fatalf("expected no error but got: %v", err)
			}

			if o.KeySize != test.expKeySize {
				t.Errorf("expected key size %d but got %d", test.expKeySize, o.KeySize)
			}

			if o.CMKeyAlgorithm != test.expCMKeyAlgo {
				t.Errorf("expected cert-manager key algorithm %q but got %q", test.expCMKeyAlgo, o.CMKeyAlgorithm)
			}

			if o.KeyAlgorithm != strings.ToUpper(test.algorithm) {
				t.Errorf("expected the algorithm to be upper-cased, but got %q", o.KeyAlgorithm)
			}
		})
	}
}
