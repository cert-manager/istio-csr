package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/sirupsen/logrus"
	pkiutil "istio.io/istio/security/pkg/pki/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager-istio-agent/pkg/util"
)

const (
	servingCertificateTTL = time.Hour * 24
	renewalTime           = (2 * servingCertificateTTL) / 3
)

type GetConfigForClientFunc func(*tls.ClientHelloInfo) (*tls.Config, error)

// tls is used to provider an automatically renewed serving certificate
type provider struct {
	log       *logrus.Entry
	client    cmclient.CertificateRequestInterface
	issuerRef cmmeta.ObjectReference

	mu        sync.RWMutex
	tlsConfig *tls.Config
}

func ConfigGetter(ctx context.Context, log *logrus.Entry, client cmclient.CertificateRequestInterface, issuerRef cmmeta.ObjectReference) (GetConfigForClientFunc, error) {
	p := &provider{
		client:    client,
		issuerRef: issuerRef,
		log:       log.WithField("module", "serving_certificate"),
	}

	p.log.Info("fetching initial serving certificate")
	p.tryFetchCertificate(ctx)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	ticker := time.NewTicker(renewalTime)

	go func() {
		for {
			p.log.Infof("renewing serving certificate in %s", renewalTime)

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			p.log.Info("renewing serving certificate")
			p.tryFetchCertificate(ctx)
		}
	}()

	return p.GetConfigForClient, nil
}

func (p *provider) tryFetchCertificate(ctx context.Context) {
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

func (p *provider) GetConfigForClient(_ *tls.ClientHelloInfo) (*tls.Config, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.tlsConfig, nil
}

func (p *provider) fetchCertificate(ctx context.Context) error {
	opts := pkiutil.CertOptions{
		Host:       "cert-manager-istio-agent.cert-manager.svc",
		IsServer:   true,
		TTL:        servingCertificateTTL,
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

	cr, err = util.WaitForCertificateRequestReady(ctx, p.client, cr.Name, time.Minute)
	if err != nil {
		return fmt.Errorf("failed to wait for CertificateRequest %s/%s to become ready: %s",
			cr.Namespace, cr.Name, err)
	}

	log.Debug("serving CertificateRequest ready")

	//go func() {
	//	if err := p.client.Delete(ctx, cr.Name, metav1.DeleteOptions{}); err != nil {
	//		log.Errorf("failed to delete serving CertificateRequest: %s", err)
	//		return
	//	}

	//	log.Debug("deleted serving CertificateRequest")
	//}()

	rootCA := x509.NewCertPool()
	rootCA.AppendCertsFromPEM(cr.Status.CA)

	tlsCert, err := tls.X509KeyPair(cr.Status.Certificate, pk)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	//p.tlsConfig = &tls.Config{
	//	//RootCAs: rootCA,
	//	//ClientCAs:    rootCA,
	//	Certificates: []tls.Certificate{tlsCert},
	//}

	p.tlsConfig = &tls.Config{
		//GetCertificate: s.getIstiodCertificate,
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		//ClientCAs:    s.peerCertVerifier.GetGeneralCertPool(),
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return nil
			//err := s.peerCertVerifier.VerifyPeerCert(rawCerts, verifiedChains)
			//if err != nil {
			//	log.Infof("Could not verify certificate: %v", err)
			//}
			//return err
		},
	}

	return nil
}
