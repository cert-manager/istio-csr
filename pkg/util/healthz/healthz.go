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
