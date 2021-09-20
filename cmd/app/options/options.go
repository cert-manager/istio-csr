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

package options

import (
	"flag"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/klogr"

	"github.com/cert-manager/istio-csr/pkg/certmanager"
	"github.com/cert-manager/istio-csr/pkg/server"
	"github.com/cert-manager/istio-csr/pkg/tls"
)

// Options is a struct to hold options for cert-manager-istio-csr
type Options struct {
	logLevel        string
	kubeConfigFlags *genericclioptions.ConfigFlags

	// ReadyzPort if the port used to expose Prometheus metrics.
	ReadyzPort int
	// ReadyzPath if the HTTP path used to expose Prometheus metrics.
	ReadyzPath string

	// MetricsPort is the port for exposing Prometheus metrics on 0.0.0.0 on the
	// path '/metrics'.
	MetricsPort int

	// Logr is the shared base logger.
	Logr logr.Logger

	// RestConfig is the shared based rest config to connect to the Kubernetes
	// API.
	RestConfig *rest.Config

	Controller  OptionsController
	CertManager certmanager.Options
	TLS         tls.Options
	Server      server.Options
}

// OptionsController is the Controller specific options
type OptionsController struct {
	// LeaderElectionNamespace is the namespace that the leader election lease is
	// held in.
	LeaderElectionNamespace string
}

func New() *Options {
	return new(Options)
}

func (o *Options) Prepare(cmd *cobra.Command) *Options {
	o.addFlags(cmd)
	return o
}

func (o *Options) Complete() error {
	klog.InitFlags(nil)
	log := klogr.New()
	flag.Set("v", o.logLevel)
	o.Logr = log

	// Ensure there is at least one DNS name to set in the serving certificate
	// to ensure clients can properly verify the serving certificate
	if len(o.TLS.ServingCertificateDNSNames) == 0 {
		return fmt.Errorf("the list of DNS names to add to the serving certificate is empty")
	}

	var err error
	o.RestConfig, err = o.kubeConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to build kubernetes rest config: %s", err)
	}

	if len(o.TLS.RootCAsCertFile) == 0 {
		log.Info("------------------------------------------------------------------------------------------------------------")
		log.Info("WARNING!: --root-ca-file is not defined which means the root CA will be discovered by the configured issuer.")
		log.Info("WARNING!: It is strongly recommended that a root CA bundle be statically defined.")
		log.Info("------------------------------------------------------------------------------------------------------------")
	}

	return nil
}

func (o *Options) addFlags(cmd *cobra.Command) {
	var nfs cliflag.NamedFlagSets

	o.addAppFlags(nfs.FlagSet("App"))
	o.addCertManagerFlags(nfs.FlagSet("cert-manager"))
	o.kubeConfigFlags = genericclioptions.NewConfigFlags(true)
	o.kubeConfigFlags.AddFlags(nfs.FlagSet("Kubernetes"))
	o.addTLSFlags(nfs.FlagSet("TLS"))
	o.addServerFlags(nfs.FlagSet("Server"))
	o.addControllerFlags(nfs.FlagSet("controller"))

	usageFmt := "Usage:\n  %s\n"
	cmd.SetUsageFunc(func(cmd *cobra.Command) error {
		fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStderr(), nfs, 0)
		return nil
	})

	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStdout(), nfs, 0)
	})

	fs := cmd.Flags()
	for _, f := range nfs.FlagSets {
		fs.AddFlagSet(f)
	}
}

func (o *Options) addAppFlags(fs *pflag.FlagSet) {
	fs.StringVarP(&o.logLevel,
		"log-level", "v", "1",
		"Log level (1-5).")

	fs.IntVar(&o.ReadyzPort,
		"readiness-probe-port", 6060,
		"Port to expose the readiness probe.")

	fs.StringVar(&o.ReadyzPath,
		"readiness-probe-path", "/readyz",
		"HTTP path to expose the readiness probe server.")

	fs.IntVar(&o.MetricsPort,
		"metrics-port", 9402,
		"Port to expose Prometheus metrics on 0.0.0.0 on path '/metrics'.")
}

func (o *Options) addTLSFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.TLS.TrustDomain,
		"trust-domain", "cluster.local",
		"The Istio cluster's trust domain.")

	fs.StringVar(&o.TLS.RootCAsCertFile, "root-ca-file", "",
		"File location of a PEM encoded Roots CA bundle to be used as root of "+
			"trust for TLS in the mesh. If empty, the CA returned from the "+
			"cert-manager issuer will be used.")

	// Here we use a duration of 1 hour by default, based on NIST 800-204A
	// recommendations (SM-DR13).
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204A.pdf
	fs.DurationVarP(&o.TLS.ServingCertificateDuration,
		"serving-certificate-duration", "t", time.Hour,
		"Certificate duration of serving certificates. Will be renewed after 2/3 of "+
			"the duration.")

	fs.StringSliceVar(&o.TLS.ServingCertificateDNSNames,
		"serving-certificate-dns-names", []string{"cert-manager-istio-csr.cert-manager.svc"},
		"A list of DNS names to request for the server's serving certificate which will be "+
			"presented to istio-agents.")

}

func (o *Options) addCertManagerFlags(fs *pflag.FlagSet) {
	fs.BoolVarP(&o.CertManager.PreserveCertificateRequests,
		"preserve-certificate-requests", "d", false,
		"If enabled, will preserve created CertificateRequests, rather than "+
			"deleting when they are ready.")

	fs.StringVarP(&o.CertManager.Namespace,
		"certificate-namespace", "c", "istio-system",
		"Namespace to request certificates.")
	fs.StringVarP(&o.CertManager.IssuerRef.Name,
		"issuer-name", "u", "istio-ca",
		"Name of the issuer to sign istio workload certificates.")
	fs.StringVarP(&o.CertManager.IssuerRef.Kind,
		"issuer-kind", "k", "Issuer",
		"Kind of the issuer to sign istio workload certificates.")
	fs.StringVarP(&o.CertManager.IssuerRef.Group,
		"issuer-group", "g", "cert-manager.io",
		"Group of the issuer to sign istio workload certificates.")
}

func (o *Options) addServerFlags(fs *pflag.FlagSet) {
	fs.StringVarP(&o.Server.ServingAddress,
		"serving-address", "a", "0.0.0.0:6443",
		"Address to serve certificates gRPC service.")

	fs.DurationVarP(&o.Server.MaximumClientCertificateDuration,
		"max-client-certificate-duration", "m", time.Hour,
		"Maximum duration a client certificate can be requested and valid for. Will "+
			"override with this value if the requested duration is larger")

	fs.StringVar(&o.Server.ClusterID, "cluster-id", "Kubernetes",
		"The ID of the istio cluster to verify.")
}

func (o *Options) addControllerFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Controller.LeaderElectionNamespace,
		"leader-election-namespace", "istio-system",
		"Namespace to use for controller leader election.")
}
