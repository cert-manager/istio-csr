package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	securityapi "istio.io/api/security/v1alpha1"
	"istio.io/istio/pkg/security"
	"istio.io/pkg/log"
)

const (
	bearerTokenPrefix = "Bearer "
)

var (
	certmanagerClientLog = log.RegisterScope("certmanagerclient", "cert-manager client debugging", 0)
)

type certmanagerClient struct {
	caEndpoint    string
	enableTLS     bool
	caTLSRootCert []byte
	client        securityapi.IstioCertificateServiceClient
	clusterID     string
	conn          *grpc.ClientConn
}

// NewCertManagerClient create a CA client for cert-manager istio agent.
func NewCertManagerClient(endpoint string, tls bool, rootCert []byte, clusterID string) (security.Client, error) {
	c := &certmanagerClient{
		caEndpoint:    endpoint,
		enableTLS:     tls,
		caTLSRootCert: rootCert,
		clusterID:     clusterID,
	}

	conn, err := c.buildConnection()
	if err != nil {
		certmanagerClientLog.Errorf("Failed to connect to endpoint %s: %v", endpoint, err)
		return nil, fmt.Errorf("failed to connect to endpoint %s", endpoint)
	}
	c.conn = conn
	c.client = securityapi.NewIstioCertificateServiceClient(conn)
	return c, nil
}

// CSR Sign calls cert-manager istio-agent to sign a CSR.
func (c *certmanagerClient) CSRSign(ctx context.Context, reqID string, csrPEM []byte, token string,
	certValidTTLInSec int64) ([]string /*PEM-encoded certificate chain*/, error) {
	req := &securityapi.IstioCertificateRequest{
		Csr:              string(csrPEM),
		ValidityDuration: certValidTTLInSec,
	}

	if token != "" {
		// add Bearer prefix, which is required by cert-manager istio agent.
		token = bearerTokenPrefix + token
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("Authorization", token, "ClusterID", c.clusterID))
	} else {
		// This may use the per call credentials, if enabled.
		err := c.reconnect()
		if err != nil {
			certmanagerClientLog.Errorf("Failed to Reconnect: %v", err)
			return nil, err
		}
	}

	resp, err := c.client.CreateCertificate(ctx, req)
	if err != nil {
		certmanagerClientLog.Errorf("Failed to create certificate: %v", err)
		return nil, err
	}

	if len(resp.CertChain) <= 1 {
		certmanagerClientLog.Errorf("CertChain length is %d, expected more than 1", len(resp.CertChain))
		return nil, errors.New("invalid response cert chain")
	}

	return resp.CertChain, nil
}

func (c *certmanagerClient) getTLSDialOption() (grpc.DialOption, error) {
	// Load the TLS root certificate from the specified file.
	// Create a certificate pool
	var certPool *x509.CertPool
	var err error
	if c.caTLSRootCert == nil {
		// No explicit certificate - assume the citadel-compatible server uses a public cert
		certPool, err = x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		certmanagerClientLog.Infoa("cert-manager client using public DNS: ", c.caEndpoint)
	} else {
		certPool = x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM(c.caTLSRootCert)
		if !ok {
			return nil, fmt.Errorf("failed to append certificates")
		}
		certmanagerClientLog.Infoa("cert-manager client using custom root: ", c.caEndpoint, " ", string(c.caTLSRootCert))
	}
	var certificate tls.Certificate
	config := tls.Config{
		Certificates: []tls.Certificate{certificate},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &certificate, nil
		},
	}
	config.RootCAs = certPool

	// For debugging on localhost (with port forward)
	if strings.Contains(c.caEndpoint, "localhost") {
		config.ServerName = "cert-manager-istio-agent.cert-manager.svc"
	}

	transportCreds := credentials.NewTLS(&config)
	return grpc.WithTransportCredentials(transportCreds), nil
}

func (c *certmanagerClient) buildConnection() (*grpc.ClientConn, error) {
	var opts grpc.DialOption
	var err error
	if c.enableTLS {
		opts, err = c.getTLSDialOption()
		if err != nil {
			return nil, err
		}
	} else {
		opts = grpc.WithInsecure()
	}

	conn, err := grpc.Dial(c.caEndpoint, opts)
	if err != nil {
		certmanagerClientLog.Errorf("Failed to connect to endpoint %s: %v", c.caEndpoint, err)
		return nil, fmt.Errorf("failed to connect to endpoint %s", c.caEndpoint)
	}

	return conn, nil
}

func (c *certmanagerClient) reconnect() error {
	err := c.conn.Close()
	if err != nil {
		return fmt.Errorf("failed to close connection")
	}

	conn, err := c.buildConnection()
	if err != nil {
		return err
	}
	c.conn = conn
	c.client = securityapi.NewIstioCertificateServiceClient(conn)
	return err
}
