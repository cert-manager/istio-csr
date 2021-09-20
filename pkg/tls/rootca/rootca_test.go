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
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jetstack/cert-manager/pkg/util/pki"
	"github.com/stretchr/testify/assert"
	"k8s.io/klog/v2/klogr"
)

func Test_Watch(t *testing.T) {
	filepath := filepath.Join(t.TempDir(), "test-cert")
	rootCAs1 := genRootCAs(t)
	rootCAs2 := genRootCAs(t)

	t.Log("writing first root CA PEM to file")
	if err := os.WriteFile(filepath, rootCAs1.PEM, 0644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	t.Log("starting watcher")
	rootCAsChan, err := Watch(ctx, klogr.New(), filepath)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("ensuring the same root CA PEM is returned from watcher")
	env1 := <-rootCAsChan
	assert.Equal(t, rootCAs1.PEM, env1.PEM)
	assert.Equal(t, rootCAs1.CertPool.Subjects(), env1.CertPool.Subjects())

	t.Log("writing a different root CAs PEM to file")
	if err := os.WriteFile(filepath, rootCAs2.PEM, 0644); err != nil {
		t.Fatal(err)
	}

	t.Log("ensuring the second root CA PEM is returned from watcher")
	env2 := <-rootCAsChan
	assert.Equal(t, rootCAs2.PEM, env2.PEM)
	assert.Equal(t, rootCAs2.CertPool.Subjects(), env2.CertPool.Subjects())
}

func Test_loadRootCAsFile(t *testing.T) {
	rootCAs := genRootCAs(t)

	tests := map[string]struct {
		filepath           func(t *testing.T, dir string) string
		existingRootCAsPEM []byte
		expRootCAs         *RootCAs
		expErr             bool
	}{
		"if the filepath doesn't exist, should error": {
			filepath:           func(t *testing.T, dir string) string { return filepath.Join(dir, "doesnt-exist") },
			existingRootCAsPEM: nil,
			expRootCAs:         nil,
			expErr:             true,
		},
		"if the data hasn't changed, return nil": {
			filepath: func(t *testing.T, dir string) string {
				path := filepath.Join(dir, "test")
				if err := os.WriteFile(path, []byte("root-certs"), 0644); err != nil {
					t.Fatal(err)
				}
				return path
			},
			existingRootCAsPEM: []byte("root-certs"),
			expRootCAs:         nil,
			expErr:             false,
		},
		"if new root cert cannot be decoded, return error": {
			filepath: func(t *testing.T, dir string) string {
				path := filepath.Join(dir, "test")
				if err := os.WriteFile(path, []byte("new-root-certs"), 0644); err != nil {
					t.Fatal(err)
				}
				return path
			},
			existingRootCAsPEM: []byte("root-certs"),
			expRootCAs:         nil,
			expErr:             true,
		},
		"return new cert if it changes": {
			filepath: func(t *testing.T, dir string) string {
				path := filepath.Join(dir, "test")
				if err := os.WriteFile(path, rootCAs.PEM, 0644); err != nil {
					t.Fatal(err)
				}
				return path
			},
			existingRootCAsPEM: []byte("root-certs"),
			expRootCAs:         &RootCAs{rootCAs.PEM, rootCAs.CertPool},
			expErr:             false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			w := &watcher{
				log:        klogr.New(),
				rootCAsPEM: test.existingRootCAsPEM,
				filepath:   test.filepath(t, t.TempDir()),
			}

			rootCA, err := w.loadRootCAsFile()
			assert.Equalf(t, test.expErr, err != nil, "%v", err)
			if test.expRootCAs == nil {
				assert.Nil(t, rootCA)
			} else {
				assert.Equal(t, test.expRootCAs.PEM, rootCA.PEM)
				assert.Equal(t, test.expRootCAs.CertPool.Subjects(), rootCA.CertPool.Subjects())
			}
		})
	}
}

func genRootCAs(t *testing.T) RootCAs {
	rootPK, err := pki.GenerateEd25519PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	rootCert := &x509.Certificate{
		Version:               2,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(0),
		Subject: pkix.Name{
			CommonName: "root-ca",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Minute),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		PublicKey: rootPK.Public(),
		IsCA:      true,
	}
	rootCertPEM, rootCert, err := pki.SignCertificate(rootCert, rootCert, rootPK.Public(), rootPK)
	if err != nil {
		t.Fatal(err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	return RootCAs{rootCertPEM, rootPool}
}
