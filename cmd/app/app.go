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

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	clientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/cert-manager/istio-csr/cmd/app/options"
	"github.com/cert-manager/istio-csr/pkg/certmanager"
	"github.com/cert-manager/istio-csr/pkg/controller"
	"github.com/cert-manager/istio-csr/pkg/server"
	"github.com/cert-manager/istio-csr/pkg/tls"
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

			cm, err := certmanager.New(opts.Logr, opts.RestConfig, opts.CertManager)
			if err != nil {
				return fmt.Errorf("failed to initialise cert-manager manager: %w", err)
			}

			intscheme := runtime.NewScheme()
			if err := scheme.AddToScheme(intscheme); err != nil {
				return fmt.Errorf("failed to add kubernetes scheme: %s", err)
			}

			cl, err := kubernetes.NewForConfig(opts.RestConfig)
			if err != nil {
				return fmt.Errorf("error creating kubernetes client: %s", err.Error())
			}

			mlog := opts.Logr.WithName("manager")
			eventBroadcaster := record.NewBroadcaster()
			eventBroadcaster.StartLogging(func(format string, args ...interface{}) { mlog.V(3).Info(fmt.Sprintf(format, args...)) })
			eventBroadcaster.StartRecordingToSink(&clientv1.EventSinkImpl{Interface: cl.CoreV1().Events("istio-system")})

			mgr, err := ctrl.NewManager(opts.RestConfig, ctrl.Options{
				Scheme:                        intscheme,
				EventBroadcaster:              eventBroadcaster,
				LeaderElection:                true,
				LeaderElectionNamespace:       opts.Controller.LeaderElectionNamespace,
				LeaderElectionID:              "istio-csr",
				LeaderElectionReleaseOnCancel: true,
				ReadinessEndpointName:         opts.ReadyzPath,
				HealthProbeBindAddress:        fmt.Sprintf("0.0.0.0:%d", opts.ReadyzPort),
				MetricsBindAddress:            fmt.Sprintf("0.0.0.0:%d", opts.MetricsPort),
				Logger:                        mlog,
			})
			if err != nil {
				return fmt.Errorf("failed to create manager: %w", err)
			}

			// Create a new TLS provider for the serving certificate and private key.
			tls, err := tls.NewProvider(opts.Logr, cm, opts.TLS)
			if err != nil {
				return fmt.Errorf("failed to create tls provider: %w", err)
			}
			if err := mgr.AddReadyzCheck("tls_provider", tls.Check); err != nil {
				return fmt.Errorf("failed to add tls provider readiness check: %w", err)
			}
			if err := mgr.Add(tls); err != nil {
				return fmt.Errorf("failed to add tls provider as runnable: %w", err)
			}

			// Create an new server instance that implements the certificate signing API
			server, err := server.New(opts.Logr, opts.RestConfig, cm, tls, opts.Server)
			if err != nil {
				return fmt.Errorf("failed to create grpc server: %w", err)
			}
			if err := mgr.AddReadyzCheck("grpc_server", server.Check); err != nil {
				return fmt.Errorf("failed to add grpc server readiness check: %w", err)
			}
			if err := mgr.Add(server); err != nil {
				return fmt.Errorf("failed to add grpc server as runnable: %w", err)
			}

			// Add the ConfigMap controller that propagates the root CAs.
			if err := controller.AddConfigMapController(ctx, opts.Logr, controller.Options{
				LeaderElectionNamespace: opts.Controller.LeaderElectionNamespace,
				TLS:                     tls,
				Manager:                 mgr,
			}); err != nil {
				return fmt.Errorf("failed to add CA root controller: %w", err)
			}

			// Start all runnable and controller
			return mgr.Start(ctx)
		},
	}

	opts = opts.Prepare(cmd)

	return cmd
}
