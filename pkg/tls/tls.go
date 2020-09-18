package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/sirupsen/logrus"
	"istio.io/istio/pkg/spiffe"
	pkiutil "istio.io/istio/security/pkg/pki/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager-istio-agent/cmd/app/options"
	"github.com/jetstack/cert-manager-istio-agent/pkg/util"
)

type GetConfigForClientFunc func(*tls.ClientHelloInfo) (*tls.Config, error)

// tls is used to provider an automatically renewed serving certificate
type Provider struct {
	log *logrus.Entry

	customRootCA          bool
	preserveCRs           bool
	servingCertificateTTL time.Duration
	rootCA                []byte

	client    cmclient.CertificateRequestInterface
	issuerRef cmmeta.ObjectReference

	mu        sync.RWMutex
	tlsConfig *tls.Config
}

func NewProvider(ctx context.Context, log *logrus.Entry, tlsOptions *options.TLSOptions,
	kubeOptions *options.KubeOptions, cmOptions *options.CertManagerOptions) (*Provider, error) {

	p := &Provider{
		log:                   log.WithField("module", "serving_certificate"),
		servingCertificateTTL: tlsOptions.ServingCertificateTTL,
		preserveCRs:           cmOptions.PreserveCRs,
		customRootCA:          len(tlsOptions.RootCACert) > 0,
		client:                kubeOptions.CMClient,
		issuerRef:             cmOptions.IssuerRef,
		rootCA:                []byte(tlsOptions.RootCACert),
	}

	p.log.Info("fetching initial serving certificate")
	p.tryFetchCertificate(ctx)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	go func() {
		for {
			renewalTime := (2 * p.servingCertificateTTL) / 3
			timer := time.NewTimer(renewalTime)

			p.log.Infof("renewing serving certificate in %s", renewalTime)

			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				timer.Stop()
			}

			p.log.Info("renewing serving certificate")
			p.tryFetchCertificate(ctx)
		}
	}()

	return p, nil
}

func (p *Provider) tryFetchCertificate(ctx context.Context) {
	ticker := time.NewTicker(time.Second * 10)

	for {
		if err := p.fetchCertificate(ctx); err != nil {
			p.log.Errorf("failed to fetch new serving certificate: %s, retrying", err)

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

func (p *Provider) GetConfigForClient(_ *tls.ClientHelloInfo) (*tls.Config, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.tlsConfig, nil
}

func (p *Provider) RootCA() []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.rootCA
}

func (p *Provider) fetchCertificate(ctx context.Context) error {
	opts := pkiutil.CertOptions{
		Host:       "cert-manager-istio-agent.cert-manager.svc",
		IsServer:   true,
		TTL:        p.servingCertificateTTL,
		RSAKeySize: 2048,
	}

	csr, pk, err := pkiutil.GenCSR(opts)
	if err != nil {
		return fmt.Errorf("failed to generate serving private key and CSR: %s", err)
	}

	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "cert-manager-istio-agent-",
			Annotations: map[string]string{
				"istio.cert-manager.io/identities": "cert-manager-istio-agent",
			},
		},
		Spec: cmapi.CertificateRequestSpec{
			Duration: &metav1.Duration{
				Duration: time.Hour * 24,
			},
			IsCA:      false,
			Request:   csr,
			Usages:    []cmapi.KeyUsage{cmapi.UsageServerAuth},
			IssuerRef: p.issuerRef,
		},
	}

	cr, err = p.client.Create(ctx, cr, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create serving CertificateRequest: %s", err)
	}

	log := util.LogWithCertificateRequest(p.log, cr)

	log.Debug("created serving CertificateRequest")

	cr, err = util.WaitForCertificateRequestReady(ctx, log, p.client, cr.Name, time.Minute)
	if err != nil {
		return fmt.Errorf("failed to wait for CertificateRequest %s/%s to become ready: %s",
			cr.Namespace, cr.Name, err)
	}

	log.Debug("serving CertificateRequest ready")

	if !p.preserveCRs {
		go func() {
			if err := p.client.Delete(ctx, cr.Name, metav1.DeleteOptions{}); err != nil {
				log.Errorf("failed to delete serving CertificateRequest: %s", err)
				return
			}

			log.Debug("deleted serving CertificateRequest")
		}()
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.customRootCA {
		p.rootCA = cr.Status.CA
	}

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

	peerCertVerifier := spiffe.NewPeerCertVerifier()
	peerCertVerifier.AddMapping(spiffe.GetTrustDomain(), []*x509.Certificate{rootCert})

	tlsCert, err := tls.X509KeyPair(cr.Status.Certificate, pk)
	if err != nil {
		return err
	}

	rootCA := x509.NewCertPool()
	rootCA.AppendCertsFromPEM(p.rootCA)

	p.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    peerCertVerifier.GetGeneralCertPool(),
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			err := peerCertVerifier.VerifyPeerCert(rawCerts, verifiedChains)
			if err != nil {
				log.Infof("Could not verify certificate: %v", err)
			}
			return err
		},
	}

	return nil
}
