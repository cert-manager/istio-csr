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
	certmanagerClientLog = log.RegisterScope("certmanagerclient", "cert-manager client debugging")
)

type certmanagerClient struct {
	caEndpoint    string
	enableTLS     bool
	caTLSRootCert []byte
	clusterID     string
	token         string

	client securityapi.IstioCertificateServiceClient
	conn   *grpc.ClientConn
}

// NewCertManagerClient create a CA client for cert-manager istio agent.
func NewCertManagerClient(endpoint, token string, tls bool, rootCert []byte, clusterID string) (security.Client, error) {
	c := &certmanagerClient{
		caEndpoint:    endpoint,
		token:         token,
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

// CSR Sign calls cert-manager istio-csr to sign a CSR.
func (c *certmanagerClient) CSRSign(csrPEM []byte, certValidTTLInSec int64) ([]string, error) {
	req := &securityapi.IstioCertificateRequest{
		Csr:              string(csrPEM),
		ValidityDuration: certValidTTLInSec,
	}
	if err := c.reconnect(); err != nil {
		return nil, err
	}
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("Authorization", bearerTokenPrefix+c.token, "ClusterID", c.clusterID))
	resp, err := c.client.CreateCertificate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %v", err)
	}

	if len(resp.GetCertChain()) <= 1 {
		return nil, errors.New("invalid empty CertChain")
	}

	return resp.GetCertChain(), nil
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
		certmanagerClientLog.Infof("cert-manager client using public DNS: %s", c.caEndpoint)
	} else {
		certPool = x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM(c.caTLSRootCert)
		if !ok {
			return nil, fmt.Errorf("failed to append certificates")
		}
		certmanagerClientLog.Infof("cert-manager client using custom root: %s %s", c.caEndpoint, string(c.caTLSRootCert))
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
		config.ServerName = "istio-csr.cert-manager.svc"
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

func (c *certmanagerClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *certmanagerClient) GetRootCertBundle() ([]string, error) {
	return []string{string(c.caTLSRootCert)}, nil
}
