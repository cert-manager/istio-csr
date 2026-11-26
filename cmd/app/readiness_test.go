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
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
)

func TestLogReadinessChanges(t *testing.T) {
	var (
		mu    sync.Mutex
		lines []string
	)
	log := funcr.New(func(prefix, args string) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, args)
	}, funcr.Options{})

	var result error
	check := logReadinessChanges(logr.Logger(log), "test", func(*http.Request) error { return result })

	call := func(err error) error {
		result = err
		return check(nil)
	}

	// Passing from the start logs nothing.
	call(nil)
	call(nil)
	if len(lines) != 0 {
		t.Fatalf("expected no logs, got %v", lines)
	}

	// Failing is logged once, repeated probes with the same error are not.
	boom := errors.New("boom")
	if err := call(boom); !errors.Is(err, boom) {
		t.Fatalf("the check result must be returned unchanged, got %v", err)
	}
	call(boom)
	call(boom)
	if len(lines) != 1 {
		t.Fatalf("expected 1 log line, got %v", lines)
	}

	// A different failure reason is logged.
	call(errors.New("other"))
	if len(lines) != 2 {
		t.Fatalf("expected 2 log lines, got %v", lines)
	}

	// Recovery is logged once.
	call(nil)
	call(nil)
	if len(lines) != 3 {
		t.Fatalf("expected 3 log lines, got %v", lines)
	}
}
