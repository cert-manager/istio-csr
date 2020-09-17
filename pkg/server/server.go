package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
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

	"github.com/jetstack/cert-manager-istio-agent/pkg/util"
)

type Server struct {
	log *logrus.Entry

	client cmclient.CertificateRequestInterface
	auther authenticate.Authenticator

	issuerRef cmmeta.ObjectReference
}

func New(log *logrus.Entry,
	client cmclient.CertificateRequestInterface,
	auther authenticate.Authenticator,
	issuerRef cmmeta.ObjectReference) *Server {

	return &Server{
		log:       log.WithField("module", "certificate_provider"),
		client:    client,
		auther:    auther,
		issuerRef: issuerRef,
	}
}

func (s *Server) Run(ctx context.Context, tlsConfig *tls.Config, listenAddress string) error {
	creds := credentials.NewTLS(tlsConfig)
	grpcServer := grpc.NewServer(grpc.Creds(creds))

	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen %s: %v", listenAddress, err)
	}

	securityapi.RegisterIstioCertificateServiceServer(grpcServer, s)

	go func() {
		<-ctx.Done()
		s.log.Info("shutting down grpc server")
		grpcServer.GracefulStop()
		s.log.Info("grpc server stopped")
	}()

	s.log.Infof("grpc serving on %s", listenAddress)

	return grpcServer.Serve(listener)
}

func (s *Server) CreateCertificate(ctx context.Context, icr *securityapi.IstioCertificateRequest) (*securityapi.IstioCertificateResponse, error) {
	caller, err := s.auther.Authenticate(ctx)
	if err != nil {
		s.log.Errorf("failed to authenticate request (%s): %s", icr.GetMetadata(), err)
		return nil, status.Error(codes.Unauthenticated, "request authenticate failure")
	}

	// TODO: validate CSR matches identities

	identities := strings.Join(caller.Identities, ",")

	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "istio-",
			Annotations: map[string]string{
				"istio.cert-manager.io/identities": identities,
			},
		},
		Spec: cmapi.CertificateRequestSpec{
			Duration: &metav1.Duration{
				Duration: time.Duration(icr.ValidityDuration) * time.Second,
			},
			IsCA:      false,
			Request:   []byte(icr.Csr),
			Usages:    []cmapi.KeyUsage{cmapi.UsageClientAuth, cmapi.UsageServerAuth},
			IssuerRef: s.issuerRef,
		},
	}

	cr, err = s.client.Create(ctx, cr, metav1.CreateOptions{})
	if err != nil {
		s.log.Errorf("failed to create CertificateRequest for %q: %s",
			identities, err)
		return nil, status.Error(codes.Internal, "failed to sign certificate request")
	}

	log := util.LogWithCertificateRequest(s.log, cr)

	cr, err = util.WaitForCertificateRequestReady(ctx, s.client, cr.Name, time.Second*30)
	if err != nil {
		return nil, status.Error(codes.DeadlineExceeded, "timeout exceeded waiting for certificate request to be signed")
	}

	respCertChain := []string{string(cr.Status.Certificate)}
	if len(cr.Status.CA) > 0 {
		respCertChain = append(respCertChain, string(cr.Status.CA))
	}
	response := &securityapi.IstioCertificateResponse{
		CertChain: respCertChain,
	}

	log.Debugf("workload CertificateRequest signed for %q", identities)

	//go func() {
	//	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	//	defer cancel()

	//	if err := s.client.Delete(ctx, cr.Name, metav1.DeleteOptions{}); err != nil {
	//		log.Errorf("failed to delete CertificateRequest %s/%s for %s: %s",
	//			cr.Namespace, cr.Name, identities, err)
	//		return
	//	}
	//	log.Debug("deleted workload CertificateRequest")
	//}()

	return response, nil
}

//func (s *Server) authorizeCSR(identities []string, csrPEM []byte) error {
//	csr, err := pkiutil.ParsePemEncodedCSR(csrPEM)
//	if err != nil {
//		return fmt.Errorf("failed to decode requesting CSR: %s", err)
//	}
//}
