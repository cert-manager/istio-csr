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

package app

import (
	"net/http"
	"sync"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

// logReadinessChanges wraps a readiness check so that a log line is written
// whenever its result changes (ready to not ready and back, or a different
// failure reason). Probes run every few seconds, so logging each call would be
// too noisy; only transitions are logged.
func logReadinessChanges(log logr.Logger, name string, check healthz.Checker) healthz.Checker {
	var (
		mu       sync.Mutex
		seen     bool
		lastFail string
	)

	return func(req *http.Request) error {
		err := check(req)

		mu.Lock()
		defer mu.Unlock()

		switch {
		case err != nil && (!seen || lastFail != err.Error()):
			log.Info("readiness check failing, istio-csr is not ready", "check", name, "reason", err.Error())
			lastFail = err.Error()
		case err == nil && seen && lastFail != "":
			log.Info("readiness check passing again", "check", name)
			lastFail = ""
		}
		seen = true

		return err
	}
}
