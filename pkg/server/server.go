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
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/go-logr/logr"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	securityapi "istio.io/api/security/v1alpha1"
	"istio.io/istio/pkg/security"

	"github.com/cert-manager/istio-csr/pkg/certmanager"
	"github.com/cert-manager/istio-csr/pkg/util"
)

const (
	IdentitiesAnnotationKey = "istio.cert-manager.io/identities"
)

type Options struct {
	// Auther is used to authenticate incoming CreateCertificate requests from
	// clients.
	Auther security.Authenticator

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

	cm     *certmanager.Manager
	readyz *util.Check
}

func New(log logr.Logger,
	cm *certmanager.Manager,
	readyz *util.Check,
	opts Options,
) *Server {
	return &Server{
		opts:   opts,
		log:    log.WithName("grpc_server").WithValues("serving_addr", opts.ServingAddress),
		cm:     cm,
		readyz: readyz,
	}
}

// Run is a blocking func that will run the client facing certificate service
func (s *Server) Run(ctx context.Context, tlsConfig *tls.Config) error {
	// Setup the grpc server using the passed TLS config
	creds := credentials.NewTLS(tlsConfig)
	grpcServer := grpc.NewServer(grpc.Creds(creds))

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
		s.readyz.Set(false)
		s.log.Info("shutting down grpc server")
		grpcServer.GracefulStop()
		s.log.Info("grpc server stopped")
	}()

	s.log.Info("grpc serving", "address", listener.Addr().String())
	s.readyz.Set(true)

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

	// Parse returned signed certificate
	respCertChain := []string{string(bundle.Certificate)}
	if len(bundle.CA) > 0 {
		// If the request returns a CA certificate, add to the response chain
		respCertChain = append(respCertChain, string(bundle.CA))
	}

	// Build client response object
	response := &securityapi.IstioCertificateResponse{
		CertChain: respCertChain,
	}

	log.V(2).Info("workload CertificateRequest signed", "identities", identities)

	// Return response to the client
	return response, nil
}
