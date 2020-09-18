package app

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jetstack/cert-manager-istio-agent/cmd/app/options"
	"github.com/jetstack/cert-manager-istio-agent/pkg/controller"
	"github.com/jetstack/cert-manager-istio-agent/pkg/server"
	agenttls "github.com/jetstack/cert-manager-istio-agent/pkg/tls"
)

const (
	helpOutput = "cert-manager istio agent for signing istio agent certificate signing requests through cert-manager"
)

func NewCommand(ctx context.Context) *cobra.Command {
	opts := new(options.Options)

	cmd := &cobra.Command{
		Use:   "cert-manager-istio-agent",
		Short: helpOutput,
		Long:  helpOutput,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Complete(); err != nil {
				return err
			}

			tlsProvider, err := agenttls.NewProvider(ctx, opts.Logr, opts.ServingCertificateTTL,
				opts.CMClient, opts.IssuerRef)
			if err != nil {
				return err
			}

			server := server.New(opts.Logr, opts.CMClient, opts.Auther, opts.IssuerRef)

			tlsConfig, err := tlsProvider.GetConfigForClient(nil)
			if err != nil {
				return err
			}

			rootCAConfigData := map[string]string{
				"root-cert.pem": fmt.Sprintf("%s", tlsProvider.RootCA()),
			}

			rootCAController := controller.NewCARootController(opts.Logr, opts.KubeClient,
				opts.Namespace, "istio-ca-root-cert", rootCAConfigData)

			id, err := os.Hostname()
			if err != nil {
				return fmt.Errorf("failed to get hostname for leader election id: %s", err)
			}
			go rootCAController.Run(ctx, id)

			return server.Run(ctx, tlsConfig, opts.ServingAddress)
		},
	}

	opts = opts.Prepare(cmd)

	return cmd
}
