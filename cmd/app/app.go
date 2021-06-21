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

package app

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cert-manager/istio-csr/cmd/app/options"
	"github.com/cert-manager/istio-csr/pkg/certmanager"
	"github.com/cert-manager/istio-csr/pkg/controller"
	"github.com/cert-manager/istio-csr/pkg/server"
	"github.com/cert-manager/istio-csr/pkg/tls"
	"github.com/cert-manager/istio-csr/pkg/util"
)

const (
	helpOutput = "cert-manager istio agent for signing istio agent certificate signing requests through cert-manager"
)

// NewCommand will return a new command instance for the istio agent.
func NewCommand(ctx context.Context) *cobra.Command {
	opts := options.New()

	cmd := &cobra.Command{
		Use:   "cert-manager-istio-csr",
		Short: helpOutput,
		Long:  helpOutput,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Complete(); err != nil {
				return err
			}

			readyz := util.New()

			cm, err := certmanager.New(opts.Logr, opts.RestConfig, opts.CertManager)
			if err != nil {
				return err
			}

			// Create a new TLS provider for the serving certificate and private key.
			tlsProvider, err := tls.NewProvider(ctx, opts.Logr, cm, readyz.Register(), opts.TLS)
			if err != nil {
				return err
			}

			// Fetch a TLS config which will be renewed transparently
			tlsConfig, err := tlsProvider.TLSConfig()
			if err != nil {
				return err
			}

			// Create an new server instance that implements the certificate signing API
			server := server.New(opts.Logr, cm, readyz.Register(), opts.Server)

			// Build the data which should be present in the well-known configmap in
			// all namespaces.
			opts.Controller.Data = map[string]string{
				"root-cert.pem": fmt.Sprintf("%s", tlsProvider.RootCA()),
			}

			// Build and run the namespace controller to distribute the root CA
			rootCAController, err := controller.NewCARootController(opts.Logr, opts.RestConfig, readyz.Check, opts.Controller)
			if err != nil {
				return fmt.Errorf("failed to create new controller: %s", err)
			}

			go func() {
				// If the controller fails to start or we lose leader election, exit
				// error
				if err := rootCAController.Run(ctx); err != nil {
					opts.Logr.Error(err, "error running root CA controller")
					os.Exit(1)
				}
			}()

			// Run the istio agent certificate signing service
			return server.Run(ctx, tlsConfig)
		},
	}

	opts = opts.Prepare(cmd)

	return cmd
}
