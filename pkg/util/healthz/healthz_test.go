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

package healthz

import (
	"testing"
)

func TestHealthz(t *testing.T) {
	tests := map[string]struct {
		checks []Check
		expOK  bool
	}{
		"if no checks registered, return not ready": {
			checks: nil,
			expOK:  false,
		},
		"if one check registered and not ready, return not ready": {
			checks: []Check{
				{false},
			},
			expOK: false,
		},
		"if one check registered and ready, return ready": {
			checks: []Check{
				{true},
			},
			expOK: true,
		},
		"if two checks registered and not ready, return not ready": {
			checks: []Check{
				{false},
				{false},
			},
			expOK: false,
		},
		"if two checks registered and one not ready, return not ready": {
			checks: []Check{
				{true},
				{false},
			},
			expOK: false,
		},
		"if two checks registered and both ready, return ready": {
			checks: []Check{
				{true},
				{true},
			},
			expOK: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			h := New()
			for _, check := range test.checks {
				h.Register().Set(check.b)
			}

			err := h.Check(nil)
			if test.expOK != (err == nil) {
				t.Errorf("unexpected response, exp=%t got=%v",
					test.expOK, err)
			}
		})
	}
}
