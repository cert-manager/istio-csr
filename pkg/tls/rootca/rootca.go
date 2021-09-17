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

package rootca

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/jetstack/cert-manager/pkg/util/pki"
)

// RootCAs is a Root CAs bundle that contains raw PEM encoded CAs, as well as
// their x509.CertPool encoding.
type RootCAs struct {
	// PEM is the raw PEM encoding of the CA certificates.
	PEM []byte

	// CertPool is the x509.CertPool encoding of the CA certificates.
	CertPool *x509.CertPool
}

// watcher is used for loading and watching a file that contains a root CAs
// bundle.
type watcher struct {
	log logr.Logger

	filepath   string
	rootCAsPEM []byte
	syncPeriod time.Duration
}

// Watch watches the given filepath for changes, and writes to the returned
// channel the new state when it changes. The first event is the initial state
// of the root CAs file.
func Watch(ctx context.Context, log logr.Logger, filepath string) (<-chan RootCAs, error) {
	return (&watcher{
		log:        log.WithName("root-ca-watcher").WithValues("file", filepath),
		filepath:   filepath,
		syncPeriod: time.Second * 10,
	}).start(ctx)
}

// start will start the watcher. First RootCAs channel event is the first
// initial file state.
func (w watcher) start(ctx context.Context) (<-chan RootCAs, error) {
	broadcastChan := make(chan RootCAs)

	w.log.Info("loading root CAs bundle")
	rootCAs, err := w.loadRootCAsFile()
	if err != nil {
		return nil, fmt.Errorf("failed to load root CA bundle: %w", err)
	}

	go func() {
		w.log.Info("starting root CAs file watcher")
		timer := time.NewTicker(w.syncPeriod)
		defer timer.Stop()

		// Send initial root CAs state
		broadcastChan <- *rootCAs
		w.rootCAsPEM = rootCAs.PEM

		for {
			select {
			case <-ctx.Done():
				w.log.Info("closing root CAs file watcher")
				return

			case <-timer.C:
				w.log.V(3).Info("checking for root CA changes on file")

				rootCAs, err := w.loadRootCAsFile()
				if err != nil {
					w.log.Error(err, "failed to load root CAs file")
				}

				if rootCAs != nil {
					w.log.Info("root CAs changed on file, broadcasting update")
					w.rootCAsPEM = rootCAs.PEM
					broadcastChan <- *rootCAs
				}
			}
		}
	}()

	return broadcastChan, nil
}

// loadRootCAsFile will read the root CAs from the configured file, and if
// changed from the previous state, will return the updated root CAs. Will
// return nil if there has been no state change.
func (w *watcher) loadRootCAsFile() (*RootCAs, error) {
	rootCAsPEM, err := os.ReadFile(w.filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read root CAs certificate file %q: %w", w.filepath, err)
	}

	// If the root CAs PEM hasn't changed, return nil
	if bytes.Equal(rootCAsPEM, w.rootCAsPEM) {
		return nil, nil
	}

	w.log.Info("updating root CAs from file")

	rootCAsCerts, err := pki.DecodeX509CertificateChainBytes(rootCAsPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode root CAs in certificate file %q: %w", w.filepath, err)
	}

	rootCAsPool := x509.NewCertPool()
	for _, rootCert := range rootCAsCerts {
		rootCAsPool.AddCert(rootCert)
	}

	return &RootCAs{rootCAsPEM, rootCAsPool}, nil
}
