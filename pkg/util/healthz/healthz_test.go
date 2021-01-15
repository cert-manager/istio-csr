package healthz

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestHealthz(t *testing.T) {
	tests := map[string]struct {
		checks  []Check
		expResp int
	}{
		"if no checks registered, return not ready": {
			checks:  nil,
			expResp: http.StatusInternalServerError,
		},
		"if one check registered and not ready, return not ready": {
			checks: []Check{
				{false},
			},
			expResp: http.StatusInternalServerError,
		},
		"if one check registered and ready, return ready": {
			checks: []Check{
				{true},
			},
			expResp: http.StatusOK,
		},
		"if two checks registered and not ready, return not ready": {
			checks: []Check{
				{false},
				{false},
			},
			expResp: http.StatusInternalServerError,
		},
		"if two checks registered and one not ready, return not ready": {
			checks: []Check{
				{true},
				{false},
			},
			expResp: http.StatusInternalServerError,
		},
		"if two checks registered and both ready, return ready": {
			checks: []Check{
				{true},
				{true},
			},
			expResp: http.StatusOK,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			h := New(logrus.NewEntry(logrus.New()), 0, "/testhealthz")
			for _, check := range test.checks {
				h.Register().Set(check.b)
			}

			ctx, cancel := context.WithCancel(context.TODO())
			defer cancel()

			if err := h.Start(ctx); err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			port, err := h.servingPort()
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			addr := fmt.Sprintf("http://127.0.0.1:%s/testhealthz", port)
			req, err := http.NewRequest("GET", addr, nil)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			if resp.StatusCode != test.expResp {
				t.Errorf("unexpected response status code, exp=%d got=%d",
					test.expResp, resp.StatusCode)
			}
		})
	}
}
