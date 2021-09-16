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

package server

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
	grpcprom "github.com/grpc-ecosystem/go-grpc-prometheus"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/util/pki"
	prom "github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	securityapi "istio.io/api/security/v1alpha1"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/jwt"
	"istio.io/istio/pkg/security"
	"istio.io/istio/security/pkg/server/ca/authenticate/kubeauth"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/cert-manager/istio-csr/pkg/certmanager"
	"github.com/cert-manager/istio-csr/pkg/tls"
)

type Options struct {
	// ClusterID is the ID of the cluster to verify requests to.
	ClusterID string

	// Address to serve the gRPC service
	ServingAddress string

	// MaximumClientCertificateDuration is the maximum duration a client can
	// request its duration for. If the client requests a duration larger than
	// this value, this value will be used instead.
	MaximumClientCertificateDuration time.Duration
}

// Server is the implementation of the istio CreateCertificate service
type Server struct {
	opts Options
	log  logr.Logger

	auther security.Authenticator

	cm  certmanager.Signer
	tls tls.Interface

	ready bool
	lock  sync.RWMutex
}

func New(log logr.Logger, restConfig *rest.Config, cm certmanager.Signer, tls tls.Interface, opts Options) (*Server, error) {

	kubeClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build kubernetes client: %s", err)
	}

	meshcnf := mesh.DefaultMeshConfig()
	meshcnf.TrustDomain = tls.TrustDomain()
	auther := kubeauth.NewKubeJWTAuthenticator(mesh.NewFixedWatcher(&meshcnf), kubeClient, opts.ClusterID, nil, jwt.PolicyThirdParty)

	return &Server{
		opts:   opts,
		log:    log.WithName("grpc_server").WithValues("serving_addr", opts.ServingAddress),
		auther: auther,
		cm:     cm,
		tls:    tls,
	}, nil
}

// Start is a blocking func that will run the client facing certificate service
func (s *Server) Start(ctx context.Context) error {
	tlsConfig, err := s.tls.Config(ctx)
	if err != nil {
		return err
	}

	// Setup the grpc server using the provided TLS config
	srvmetrics := grpcprom.NewServerMetrics(func(op *prom.CounterOpts) { op.Namespace = "cert_manager_istio_csr" })
	srvmetrics.EnableHandlingTimeHistogram(func(op *prom.HistogramOpts) { op.Namespace = "cert_manager_istio_csr" })
	creds := credentials.NewTLS(tlsConfig)
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(srvmetrics.UnaryServerInterceptor()),
		grpc.Creds(creds),
	)

	// Register gRPC Prometheus metrics
	grpcprom.Register(grpcServer)
	if err := metrics.Registry.Register(srvmetrics); err != nil {
		return fmt.Errorf("failed to register gRPC Prometheus metrics: %w", err)
	}

	// listen on the configured address
	listener, err := net.Listen("tcp", s.opts.ServingAddress)
	if err != nil {
		return fmt.Errorf("failed to listen %s: %v", s.opts.ServingAddress, err)
	}

	// register certificate service grpc API
	securityapi.RegisterIstioCertificateServiceServer(grpcServer, s)

	// handle termination gracefully
	go func() {
		<-ctx.Done()

		s.lock.Lock()
		s.ready = false
		s.lock.Unlock()

		s.log.Info("shutting down grpc server", "context", ctx.Err())
		grpcServer.GracefulStop()
		s.log.Info("grpc server stopped")
	}()

	s.log.Info("grpc serving", "address", listener.Addr().String())

	s.lock.Lock()
	s.ready = true
	s.lock.Unlock()

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

	log := s.log.WithValues("identities", identities)

	// If requested duration is larger than the maximum value, override with the
	// maxiumum value.
	duration := time.Duration(icr.ValidityDuration) * time.Second
	if duration > s.opts.MaximumClientCertificateDuration {
		duration = s.opts.MaximumClientCertificateDuration
	}

	bundle, err := s.cm.Sign(ctx, identities, []byte(icr.Csr), duration, []cmapi.KeyUsage{cmapi.UsageClientAuth, cmapi.UsageServerAuth})
	if err != nil {
		log.Error(err, "failed to sign incoming client certificate signing request")
		return nil, status.Error(codes.Internal, "failed to sign certificate request")
	}

	certChain, err := s.parseCertificateBundle(bundle)
	if err != nil {
		log.Error(err, "failed to parse and verify signed certificate chain from issuer")
		return nil, status.Error(codes.Internal, "failed to parse and verify signed certificate from issuer")
	}

	// Build client response object
	response := &securityapi.IstioCertificateResponse{
		CertChain: certChain,
	}

	log.V(2).Info("workload CertificateRequest signed")

	// Return response to the client
	return response, nil
}

// All istio-csr's should serve the CreateCertificate service
func (s *Server) NeedLeaderElection() bool {
	return false
}

// Check is used by the shared readiness manager to expose whether the server
// is ready.
func (s *Server) Check(_ *http.Request) error {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.ready {
		return nil
	}
	return errors.New("not ready")
}

// parseCertificateChain will attempt to parse the certmanager certificate
// bundle, and return a chain of certificates with the last being the root CAs
// bundle.
// This function will ensure the chain is a flat linked list, and is valid for
// at least one of the root CAs.
func (s *Server) parseCertificateBundle(bundle certmanager.Bundle) ([]string, error) {
	// Parse returned signed certificate chain. Append root CA validate it is a
	// flat chain.
	respBundle, err := pki.ParseSingleCertificateChainPEM(bundle.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and verify chain returned from issuer: %w", err)
	}

	// Verify that the signed chain is a member of one of the root CAs.
	respCerts, err := pki.DecodeX509CertificateChainBytes(respBundle.ChainPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate chain returned from issuer: %w", err)
	}

	intermediatePool := x509.NewCertPool()
	for _, intermediate := range respCerts[1:] {
		intermediatePool.AddCert(intermediate)
	}

	rootCAsPEM, rootCAsPool := s.tls.RootCAs()
	opts := x509.VerifyOptions{
		Intermediates: intermediatePool,
		Roots:         rootCAsPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	if _, err := respCerts[0].Verify(opts); err != nil {
		return nil, fmt.Errorf("failed to verify the issued certificate chain against the current mesh roots: %w", err)
	}

	// Build the certificate chain, and tag on the rootCAs as the last entry.
	var certChain []string
	for _, cert := range respCerts {
		certEncoded, err := pki.EncodeX509(cert)
		if err != nil {
			return nil, fmt.Errorf("failed to encode signed certificate: %w", err)
		}
		certChain = append(certChain, string(certEncoded))
	}

	return append(certChain, string(rootCAsPEM)), nil
}
