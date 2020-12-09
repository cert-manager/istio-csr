package app

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cert-manager/istio-csr/cmd/app/options"
	"github.com/cert-manager/istio-csr/pkg/controller"
	"github.com/cert-manager/istio-csr/pkg/server"
	agenttls "github.com/cert-manager/istio-csr/pkg/tls"
)

const (
	helpOutput = "cert-manager istio agent for signing istio agent certificate signing requests through cert-manager"
)

// NewCommand will return a new command instance for the istio agent.
func NewCommand(ctx context.Context) *cobra.Command {
	opts := options.New()

	cmd := &cobra.Command{
		Use:   "cert-manager-istio-agent",
		Short: helpOutput,
		Long:  helpOutput,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Complete(); err != nil {
				return err
			}

			// Create a new TLS provider for the serving certificate and private key.
			tlsProvider, err := agenttls.NewProvider(ctx, opts.Logr, opts.TLSOptions,
				opts.KubeOptions, opts.CertManagerOptions)
			if err != nil {
				return err
			}

			// Fetch a TLS config which will be renewed transparently
			tlsConfig, err := tlsProvider.TLSConfig()
			if err != nil {
				return err
			}

			// Create an new server instance that implements the certificate signing API
			server := server.New(opts.Logr, opts.CertManagerOptions, opts.KubeOptions)

			// Build the data which should be present in the well-known configmap in
			// all namespaces.
			rootCAConfigData := map[string]string{
				"root-cert.pem": fmt.Sprintf("%s", tlsProvider.RootCA()),
			}

			// Build and run the namespace controller to distribute the root CA
			rootCAController := controller.NewCARootController(opts.Logr, opts.KubeOptions,
				opts.Namespace, opts.RootCAConfigMapName, rootCAConfigData)

			id, err := os.Hostname()
			if err != nil {
				return fmt.Errorf("failed to get hostname for leader election id: %s", err)
			}
			go rootCAController.Run(ctx, id)

			// Run the istio agent certificate signing service
			return server.Run(ctx, tlsConfig, opts.ServingAddress)
		},
	}

	opts = opts.Prepare(cmd)

	return cmd
}
