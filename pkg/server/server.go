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
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	securityapi "istio.io/api/security/v1alpha1"
	"istio.io/istio/security/pkg/server/ca/authenticate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cert-manager/istio-csr/cmd/app/options"
	"github.com/cert-manager/istio-csr/pkg/util"
	"github.com/cert-manager/istio-csr/pkg/util/healthz"
)

const (
	IdentitiesAnnotationKey = "istio.cert-manager.io/identities"
)

// Server is the implementation of the istio CreateCertificate service
type Server struct {
	log logr.Logger

	client cmclient.CertificateRequestInterface
	auther authenticate.Authenticator

	maxDuration time.Duration

	issuerRef   cmmeta.ObjectReference
	preserveCRs bool

	readyz *healthz.Check
}

func New(log logr.Logger,
	cmOptions *options.CertManagerOptions,
	kubeOptions *options.KubeOptions,
	readyz *healthz.Check,
) *Server {
	return &Server{
		log:         log.WithName("certificate-provider"),
		client:      kubeOptions.CMClient,
		auther:      kubeOptions.Auther,
		maxDuration: cmOptions.MaximumClientCertificateDuration,
		issuerRef:   cmOptions.IssuerRef,
		preserveCRs: cmOptions.PreserveCRs,
		readyz:      readyz,
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

	// If requested duration is larger than the maximum value, override with the
	// maxiumum value.
	duration := time.Duration(icr.ValidityDuration) * time.Second
	if duration > s.maxDuration {
		duration = s.maxDuration
	}

	// Build cert-manager CertificateRequest based on the configured issuer
	cr := &cmapi.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			// Random non-conflicted name
			GenerateName: "istio-",
			Annotations: map[string]string{
				// Label identities to resource for auditing
				IdentitiesAnnotationKey: identities,
			},
		},
		Spec: cmapi.CertificateRequestSpec{
			Duration: &metav1.Duration{
				// Add duration which was requested from the client.
				Duration: duration,
			},
			IsCA:      false,
			Request:   []byte(icr.Csr),
			Usages:    []cmapi.KeyUsage{cmapi.UsageClientAuth, cmapi.UsageServerAuth},
			IssuerRef: s.issuerRef,
		},
	}

	// Create CertificateRequest
	cr, err := s.client.Create(ctx, cr, metav1.CreateOptions{})
	if err != nil {
		s.log.Error(err, "failed to create CertificateRequest for %q", identities)
		return nil, status.Error(codes.Internal, "failed to sign certificate request")
	}

	log := s.log.WithValues("namespace", cr.Namespace, "name", cr.Name)

	// If we are not preserving created CertificateRequests which have either
	// successully been signed or failed, delete in Kubernetes
	defer func() {
		go s.deleteOrPreserveCertificateRequest(log, cr)
	}()

	// Wait for a minute for the CertificateRequest to become ready
	cr, err = util.WaitForCertificateRequestReady(ctx, log, s.client, cr.Name, time.Minute)
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

	log.V(3).Info("workload CertificateRequest signed", "identities", identities)

	// Return response to the client
	return response, nil
}

// deleteOrPreserveCertificateRequest will delete the given CertificateRequest
// if server not configured to preserve. Exit early if server configured to
// preserve, or passed CertificateRequest is nil.
func (s *Server) deleteOrPreserveCertificateRequest(log logr.Logger, cr *cmapi.CertificateRequest) {
	if s.preserveCRs || cr == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	if err := s.client.Delete(ctx, cr.Name, metav1.DeleteOptions{}); err != nil {
		log.Error(err, "failed to delete CertificateRequest")
		return
	}

	log.V(3).Info("deleted workload CertificateRequest")
}
