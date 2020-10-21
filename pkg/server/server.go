package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	securityapi "istio.io/api/security/v1alpha1"
	"istio.io/istio/security/pkg/server/ca/authenticate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jetstack/cert-manager-istio-agent/cmd/app/options"
	"github.com/jetstack/cert-manager-istio-agent/pkg/util"
)

// Server is the implementation of the istio CreateCertificate service
type Server struct {
	log *logrus.Entry

	client cmclient.CertificateRequestInterface
	auther authenticate.Authenticator

	issuerRef   cmmeta.ObjectReference
	preserveCRs bool
}

func New(log *logrus.Entry, cmOptions *options.CertManagerOptions, kubeOptions *options.KubeOptions) *Server {
	return &Server{
		log:         log.WithField("module", "certificate_provider"),
		client:      kubeOptions.CMClient,
		auther:      kubeOptions.Auther,
		issuerRef:   cmOptions.IssuerRef,
		preserveCRs: cmOptions.PreserveCRs,
	}
}

// Run is a blocking func that will run the client facing certificate service
func (s *Server) Run(ctx context.Context, tlsConfig *tls.Config, listenAddress string) error {
	// Setup the grpc server using the passed TLS config
	creds := credentials.NewTLS(tlsConfig)
	grpcServer := grpc.NewServer(grpc.Creds(creds))

	// listen on the configured address
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen %s: %v", listenAddress, err)
	}

	// register certificate service grpc API
	securityapi.RegisterIstioCertificateServiceServer(grpcServer, s)

	// handle termination gracefully
	go func() {
		<-ctx.Done()
		s.log.Info("shutting down grpc server")
		grpcServer.GracefulStop()
		s.log.Info("grpc server stopped")
	}()

	s.log.Infof("grpc serving on %s", listener.Addr())

	return grpcServer.Serve(listener)
}

// CreateCertificate is the istio grpc API func, to authenticate, authorize,
// and sign CSRs requests from istio clients.
func (s *Server) CreateCertificate(ctx context.Context, icr *securityapi.IstioCertificateRequest) (*securityapi.IstioCertificateResponse, error) {
	// authn incoming requests, and build concatenated identities for labelling
	identities, ok := s.authRequest(ctx, []byte(icr.Csr))
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "request authenticate failure")
	}

	// Build cert-manager CertificateRequest based on the configured issuer
	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			// Random non-conflicted name
			GenerateName: "istio-",
			Annotations: map[string]string{
				// Label identities to resource for auditing
				"istio.cert-manager.io/identities": identities,
			},
		},
		Spec: cmapi.CertificateRequestSpec{
			Duration: &metav1.Duration{
				// Add during which was requested from the client.
				// TODO: We should have a configurable maximum that the duration can
				// be. Take smaller of the two.
				Duration: time.Duration(icr.ValidityDuration) * time.Second,
			},
			IsCA:      false,
			Request:   []byte(icr.Csr),
			Usages:    []cmapi.KeyUsage{cmapi.UsageClientAuth, cmapi.UsageServerAuth},
			IssuerRef: s.issuerRef,
		},
	}

	// Create CertificateRequest and wait for it to become ready
	cr, err := s.client.Create(ctx, cr, metav1.CreateOptions{})
	if err != nil {
		s.log.Errorf("failed to create CertificateRequest for %q: %s",
			identities, err)
		return nil, status.Error(codes.Internal, "failed to sign certificate request")
	}

	log := util.LogWithCertificateRequest(s.log, cr)

	cr, err = util.WaitForCertificateRequestReady(ctx, log, s.client, cr.Name, time.Second*30)
	if err != nil {
		return nil, status.Error(codes.DeadlineExceeded, "timeout exceeded waiting for certificate request to be signed")
	}

	// Parse returned signed certificate
	respCertChain := []string{string(cr.Status.Certificate)}
	if len(cr.Status.CA) > 0 {
		// If the request returns a CA certificate, add to the response chain
		respCertChain = append(respCertChain, string(cr.Status.CA))
	}

	// Build client response object
	response := &securityapi.IstioCertificateResponse{
		CertChain: respCertChain,
	}

	log.Debugf("workload CertificateRequest signed for %q", identities)

	// If we are not preserving created CertificateRequests which have been
	// successully signed, delete in Kubernetes
	if !s.preserveCRs {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()

			if err := s.client.Delete(ctx, cr.Name, metav1.DeleteOptions{}); err != nil {
				log.Errorf("failed to delete CertificateRequest %s/%s for %s: %s",
					cr.Namespace, cr.Name, identities, err)
				return
			}
			log.Debug("deleted workload CertificateRequest")
		}()
	}

	// Return response to the client
	return response, nil
}
