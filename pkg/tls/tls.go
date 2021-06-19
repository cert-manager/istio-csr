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

package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	"istio.io/istio/pkg/spiffe"
	pkiutil "istio.io/istio/security/pkg/pki/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/istio-csr/cmd/app/options"
	"github.com/cert-manager/istio-csr/pkg/util"
)

// Provider is used to provide a tls config containing an automatically renewed
// private key and certificate. The provider will continue to renew the signed
// certificate and private in the background, while consumers can transparently
// use an exposed TLS config. Consumers *MUST* using this config as is, in
// order for the certificate and private key be renewed transparently.
type Provider struct {
	log logr.Logger

	customRootCA          bool
	preserveCRs           bool
	servingCertificateTTL time.Duration
	dnsNames              []string
	rootCA                []byte

	client    cmclient.CertificateRequestInterface
	issuerRef cmmeta.ObjectReference

	lock      sync.RWMutex
	tlsConfig *tls.Config
}

// NewProvider will return a new provider where a TLS config is ready to be fetched.
func NewProvider(log logr.Logger,
	cmOptions *options.CertManagerOptions,
	kubeOptions *options.KubeOptions,
	tlsOptions *options.TLSOptions,
) (*Provider, error) {

	p := &Provider{
		log: log.WithName("tls_provider"),

		servingCertificateTTL: tlsOptions.ServingCertificateDuration,
		dnsNames:              tlsOptions.ServingCertificateDNSNames,
		preserveCRs:           cmOptions.PreserveCRs,
		customRootCA:          len(tlsOptions.RootCACertFile) > 0,
		client:                kubeOptions.CMClient,
		issuerRef:             cmOptions.IssuerRef,
	}

	if len(tlsOptions.RootCACertFile) > 0 {
		rootCA, err := ioutil.ReadFile(tlsOptions.RootCACertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read root CA certificate file %s: %s",
				tlsOptions.RootCACertFile, err)
		}

		p.rootCA = rootCA
	}

	p.log.Info("fetching initial serving certificate")

	return p, nil
}

// Start will start the TLS provider.
func (p *Provider) Start(ctx context.Context) error {
	// Before returning with the provider, we set a valid, up-to-date TLS
	// config is ready for serving.
	notAfter, err := p.fetchCertificate(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch initial serving certificate: %w", err)
	}

	p.log.Info("fetched initial serving certificate")

	for {
		// Create a new timer every loop. Renew 2/3 into certificate duration
		renewalTime := (2 * notAfter.Sub(time.Now())) / 3
		timer := time.NewTimer(renewalTime)

		if !notAfter.IsZero() {
			p.log.Info("waiting to renew certificate", "renewal-time", time.Now().Add(renewalTime))
		}

		select {
		case <-ctx.Done():
			p.log.Info("closing renewal", "context", ctx.Err())
			timer.Stop()
			return nil

		case <-timer.C:
			// Ensure we stop the timer after every tick to release resources
			timer.Stop()
		}

		// Renew certificate at every tick
		p.log.Info("renewing serving certificate")
		notAfter = p.mustFetchCertificate(ctx)
		p.log.Info("fetched new serving certificate", "expiry-time", notAfter)
	}
}

// mustFetchCertificate is a blocking func that will fetch a signed certificate
// for serving. Will not return until a signed certificate has been
// successfully fetched, or the context had been canceled.
// Returns the NotAfter timestamp of the signed certificate.
func (p *Provider) mustFetchCertificate(ctx context.Context) time.Time {
	// Time to attempt to fetch a new certificate if the last failed.
	ticker := time.NewTicker(time.Second * 20)
	defer ticker.Stop()

	for {
		// Fetch a new serving certificate, signed by cert-manager.
		notAfter, err := p.fetchCertificate(ctx)
		if err != nil {
			p.log.Error(err, "failed to fetch new serving certificate, retrying")

			// Cancel if the context has been canceled. Retry after tick.
			select {
			case <-ctx.Done():
				return time.Time{}
			case <-ticker.C:
				continue
			}
		}

		return notAfter
	}
}

// Config should be used by consumers of the provider to get a TLS config
// which will have the signed certificate and private key appropriately
// renewed. This function will block until a TLS config is ready.
func (p *Provider) Config() *tls.Config {
	for {
		p.lock.RLock()
		conf := p.tlsConfig
		p.lock.RUnlock()

		if conf == nil {
			time.Sleep(time.Second)
			continue
		}

		return &tls.Config{
			GetConfigForClient: p.getConfigForClient,
			ClientAuth:         tls.RequireAndVerifyClientCert,
		}
	}
}

// getConfigForClient will return a TLS config based upon the current signed
// certificate and private key the provider holds.
func (p *Provider) getConfigForClient(_ *tls.ClientHelloInfo) (*tls.Config, error) {
	p.lock.RLock()
	defer p.lock.RUnlock()
	return p.tlsConfig, nil
}

// RootCA returns the configured CA certificate. This function blocks until the
// root CA has been populated.
func (p *Provider) RootCA() []byte {
	for {
		p.lock.RLock()
		rootCA := p.rootCA
		p.lock.RUnlock()

		if len(rootCA) == 0 {
			time.Sleep(time.Second)
			continue
		}

		return rootCA
	}
}

// fetchCertificate will attempt to fetch a new signed certificate with a new
// private key for serving. This will then be stored as the latest TLS config
// for this provider to be fetched by new client connections. If this process
// fails, returns error.
// Returns the NotAfter timestamp that the new signed certificate expires.
func (p *Provider) fetchCertificate(ctx context.Context) (time.Time, error) {
	opts := pkiutil.CertOptions{
		Host:       strings.Join(p.dnsNames, ","),
		IsServer:   true,
		TTL:        p.servingCertificateTTL,
		RSAKeySize: 2048,
	}

	// Generate new CSR and private key for serving
	csr, pk, err := pkiutil.GenCSR(opts)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to generate serving private key and CSR: %s", err)
	}

	// Build the CertificateRequest for a serving certificate for this agent
	// using the configured issuer.
	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "cert-manager-istio-csr-",
			Annotations: map[string]string{
				"istio.cert-manager.io/identities": "cert-manager-istio-csr",
			},
		},
		Spec: cmapi.CertificateRequestSpec{
			Duration: &metav1.Duration{
				Duration: p.servingCertificateTTL,
			},
			IsCA:      false,
			Request:   csr,
			Usages:    []cmapi.KeyUsage{cmapi.UsageServerAuth},
			IssuerRef: p.issuerRef,
		},
	}

	// Create CertificateRequest and wait for it to be successfully signed.
	cr, err = p.client.Create(ctx, cr, metav1.CreateOptions{})
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to create serving CertificateRequest: %s", err)
	}

	log := p.log.WithValues("namespace", cr.Namespace, "name", cr.Name)
	log.Info("created serving CertificateRequest")

	cr, err = util.WaitForCertificateRequestReady(ctx, log, p.client, cr.Name, time.Minute)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to wait for CertificateRequest %s/%s to become ready: %s",
			cr.Namespace, cr.Name, err)
	}

	log.Info("serving CertificateRequest ready")

	// If we are no preserving CertificateRequests, delete from Kubernetes
	if !p.preserveCRs {
		go func() {
			if err := p.client.Delete(ctx, cr.Name, metav1.DeleteOptions{}); err != nil {
				log.Error(err, "failed to delete serving CertificateRequest")
				return
			}

			log.Info("deleted serving CertificateRequest")
		}()
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	// If we are not using a custom root CA, then overwrite the existing with
	// what was responded.
	if !p.customRootCA {
		p.rootCA = cr.Status.CA
	}

	// Parse the root CA if it exists
	var rootCert *x509.Certificate
	if len(p.rootCA) > 0 {
		block, _ := pem.Decode(p.rootCA)
		if block == nil {
			return time.Time{}, errors.New("failed to decode root cert PEM")
		}
		rootCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, fmt.Errorf("failed to parse certificate: %v", err)
		}
	}

	// Build the client certificate verifier based upon the root certificate
	peerCertVerifier := spiffe.NewPeerCertVerifier()
	peerCertVerifier.AddMapping(spiffe.GetTrustDomain(), []*x509.Certificate{rootCert})

	tlsCert, err := tls.X509KeyPair(cr.Status.Certificate, pk)
	if err != nil {
		return time.Time{}, err
	}

	rootCA := x509.NewCertPool()
	rootCA.AppendCertsFromPEM(p.rootCA)

	// Build the actual TLS config which will be used for serving and exposed by
	// this provider. This config will serve using the just signed certificate
	// and private key. Mutually authenticate incoming client requests based if a
	// certificate is present.
	p.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    peerCertVerifier.GetGeneralCertPool(),
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			err := peerCertVerifier.VerifyPeerCert(rawCerts, verifiedChains)
			if err != nil {
				log.Error(err, "could not verify certificate")
			}
			return err
		},
	}

	cert, err := pki.DecodeX509CertificateBytes(cr.Status.Certificate)
	if err != nil {
		return time.Time{}, err
	}

	return cert.NotAfter, nil
}

// All istio-csr's need renewed service certificates.
func (p *Provider) NeedLeaderElection() bool {
	return false
}

func (p *Provider) Check(_ *http.Request) error {
	p.lock.RLock()
	defer p.lock.RUnlock()

	if p.tlsConfig != nil {
		return nil
	}

	return errors.New("not ready")
}
