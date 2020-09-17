package app

import (
	"context"
	//"crypto/tls"

	"github.com/spf13/cobra"

	"github.com/jetstack/cert-manager-istio-agent/cmd/app/options"
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

			configGetter, err := agenttls.ConfigGetter(ctx, opts.Logr, opts.CMClient, opts.IssuerRef)
			if err != nil {
				return err
			}

			server := server.New(opts.Logr, opts.CMClient, opts.Auther, opts.IssuerRef)

			tlsConfig, err := configGetter(nil)
			if err != nil {
				return err
			}
			//tlsConfig := &tls.Config{
			//	GetConfigForClient: configGetter,
			//}

			return server.Run(ctx, tlsConfig, opts.ServingAddress)
		},
	}

	opts = opts.Prepare(cmd)

	return cmd
}
