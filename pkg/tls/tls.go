package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	"github.com/go-logr/logr"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"istio.io/istio/pkg/spiffe"
	pkiutil "istio.io/istio/security/pkg/pki/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/istio-csr/cmd/app/options"
	"github.com/cert-manager/istio-csr/pkg/util"
	"github.com/cert-manager/istio-csr/pkg/util/healthz"
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
	rootCA                []byte

	client    cmclient.CertificateRequestInterface
	issuerRef cmmeta.ObjectReference

	mu        sync.RWMutex
	readyz    *healthz.Check
	tlsConfig *tls.Config
}

// NewProvider will return a new provider where a TLS config is ready to be fetched.
func NewProvider(ctx context.Context, log logr.Logger, tlsOptions *options.TLSOptions,
	kubeOptions *options.KubeOptions, cmOptions *options.CertManagerOptions,
	readyz *healthz.Check) (*Provider, error) {

	p := &Provider{
		log: log.WithName("serving_certificate"),

		servingCertificateTTL: tlsOptions.ServingCertificateDuration,
		preserveCRs:           cmOptions.PreserveCRs,
		customRootCA:          len(tlsOptions.RootCACertFile) > 0,
		client:                kubeOptions.CMClient,
		issuerRef:             cmOptions.IssuerRef,
		readyz:                readyz,
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

	// Before returning with the provider, we unser a valid, up-to-date TLS
	// config is ready for serving.
	p.mustFetchCertificate(ctx)

	go func() {
		for {
			// Create a new timer every loop. Renew 2/3 into certificate duration
			renewalTime := (2 * p.servingCertificateTTL) / 3
			timer := time.NewTimer(renewalTime)

			p.log.Info("renewing serving certificate", "renewal-time", renewalTime)

			select {
			case <-ctx.Done():
				p.readyz.Set(false)
				p.log.Info("closing renewal", "ctx", ctx.Err())
				timer.Stop()
				return
			case <-timer.C:
				// Ensure we stop the timer after every tick to release resources
				timer.Stop()
			}

			// Renew certificate at every tick
			p.log.Info("renewing serving certificate")
			p.mustFetchCertificate(ctx)
		}
	}()

	p.readyz.Set(true)

	return p, nil
}

// mustFetchCertificate is a blocking func that will fetch a signed certificate
// for serving. Will not return until a signed certificate has been
// successfully fetched, for the context had been canceled.
func (p *Provider) mustFetchCertificate(ctx context.Context) {
	// Time to attempt to fetch a new certificate if the last failed.
	ticker := time.NewTicker(time.Second * 20)
	defer ticker.Stop()

	for {
		// Fetch a new serving certificate, signed by cert-manager.
		if err := p.fetchCertificate(ctx); err != nil {
			p.log.Error(err, "failed to fetch new serving certificate, retrying")

			// Cancel if the context has been canceled. Retry after tick.
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				continue
			}
		}

		p.log.Info("fetched new serving certificate")

		return
	}
}

// TLSConfig should be used by consumers of the provider to get a TLS config
// which will have the signed certificate and private key appropriately renewed
func (p *Provider) TLSConfig() (*tls.Config, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.tlsConfig == nil {
		return nil, errors.New("provider not configured, TLS config not ready")
	}

	return &tls.Config{
		GetConfigForClient: p.getConfigForClient,
		ClientAuth:         tls.RequireAndVerifyClientCert,
	}, nil
}

// getConfigForClient will return a TLS config based upon the current signed
// certificate and private key the provider holds.
func (p *Provider) getConfigForClient(_ *tls.ClientHelloInfo) (*tls.Config, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.tlsConfig, nil
}

// RootCA returns the configured CA certificate
func (p *Provider) RootCA() []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.rootCA
}

// fetchCertificate will attempt to fetch a new signed certificate with a new
// private key for serving. This will then be stored as the latest TLS config
// for this provider to be fetched by new client connections. If this process
// fails, returns error.
func (p *Provider) fetchCertificate(ctx context.Context) error {
	opts := pkiutil.CertOptions{
		// TODO: allow configurable namespace and service
		Host:       "cert-manager-istio-csr.cert-manager.svc",
		IsServer:   true,
		TTL:        p.servingCertificateTTL,
		RSAKeySize: 2048,
	}

	// Generate new CSR and private key for serving
	csr, pk, err := pkiutil.GenCSR(opts)
	if err != nil {
		return fmt.Errorf("failed to generate serving private key and CSR: %s", err)
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
		return fmt.Errorf("failed to create serving CertificateRequest: %s", err)
	}

	log := p.log.WithValues("namespace", cr.Namespace, "name", cr.Name)
	log.Info("created serving CertificateRequest")

	cr, err = util.WaitForCertificateRequestReady(ctx, log, p.client, cr.Name, time.Minute)
	if err != nil {
		return fmt.Errorf("failed to wait for CertificateRequest %s/%s to become ready: %s",
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

	p.mu.Lock()
	defer p.mu.Unlock()

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
			return fmt.Errorf("failed to decode root cert PEM")
		}
		rootCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}
	}

	// Build the client certificate verifier based upon the root certificate
	peerCertVerifier := spiffe.NewPeerCertVerifier()
	peerCertVerifier.AddMapping(spiffe.GetTrustDomain(), []*x509.Certificate{rootCert})

	tlsCert, err := tls.X509KeyPair(cr.Status.Certificate, pk)
	if err != nil {
		return err
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

	return nil
}
