package healthz

import (
	"errors"
	"net/http"
	"sync"
)

// Healthz is used to maintain and expose a readiness probe
type Healthz struct {
	mu     sync.RWMutex
	checks []*Check
}

// Check holds a single check of a readiness probe
type Check struct {
	b bool
}

func New() *Healthz {
	return new(Healthz)
}

// Register will add another check to the healthz list
func (h *Healthz) Register() *Check {
	h.mu.Lock()
	defer h.mu.Unlock()

	check := new(Check)
	h.checks = append(h.checks, check)

	return check
}

func (h *Healthz) Check(_ *http.Request) error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(h.checks) == 0 {
		return errors.New("not ok")
	}

	for _, check := range h.checks {
		if !check.b {
			return errors.New("not ok")
		}
	}

	return nil
}

func (c *Check) Set(ready bool) {
	c.b = ready
}
