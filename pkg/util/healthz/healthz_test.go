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
