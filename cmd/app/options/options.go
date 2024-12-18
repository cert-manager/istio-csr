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
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	istiolog "istio.io/istio/pkg/log"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"
	cliflag "k8s.io/component-base/cli/flag"
	logsapi "k8s.io/component-base/logs/api/v1"
	"k8s.io/klog/v2"

	"github.com/cert-manager/istio-csr/pkg/certmanager"
	"github.com/cert-manager/istio-csr/pkg/istiodcert"
	"github.com/cert-manager/istio-csr/pkg/server"
	"github.com/cert-manager/istio-csr/pkg/tls"

	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

// Options is a struct to hold options for cert-manager-istio-csr
type Options struct {
	logLevel        uint32
	logFormat       string
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
	IstiodCert  istiodcert.Options
}

// OptionsController is the Controller specific options
type OptionsController struct {
	// LeaderElectionNamespace is the namespace that the leader election lease is
	// held in.
	LeaderElectionNamespace string

	// ConfigMapNamespaceSelector is the selector to filter on the namespaces that
	// receives the istio-root-ca ConfigMap
	ConfigMapNamespaceSelector string

	// DisableKubernetesClientRateLimiter allows the default client-go rate limiter to be disabled
	// if the Kubernetes API server supports
	// [API Priority and Fairness](https://kubernetes.io/docs/concepts/cluster-administration/flow-control/).
	DisableKubernetesClientRateLimiter bool
}

func New() *Options {
	return new(Options)
}

func (o *Options) Prepare(cmd *cobra.Command) *Options {
	o.addFlags(cmd)
	return o
}

func (o *Options) Complete() error {
	logOpts := logsapi.NewLoggingConfiguration()
	istioLogOptions := istiolog.DefaultOptions()

	if o.logFormat == "" {
		o.logFormat = "text"
	}

	o.logFormat = strings.ToLower(o.logFormat)
	if o.logFormat != "json" && o.logFormat != "text" {
		return fmt.Errorf("invalid log-format; must be either \"text\" or \"json\"")
	}

	logOpts.Format = o.logFormat

	logOpts.Verbosity = logsapi.VerbosityLevel(o.logLevel)

	if o.logFormat == "json" {
		istioLogOptions.JSONEncoding = true
	}

	err := logsapi.ValidateAndApply(logOpts, nil)
	if err != nil {
		return fmt.Errorf("failed to set log config: %w", err)
	}

	klog.InitFlags(nil)
	log := klog.TODO()
	o.Logr = log

	err = istiolog.Configure(istioLogOptions)
	if err != nil {
		return fmt.Errorf("failed to configure istio logging: %w", err)
	}

	// Ensure there is at least one DNS name to set in the serving certificate
	// to ensure clients can properly verify the serving certificate
	if len(o.TLS.ServingCertificateDNSNames) == 0 {
		return fmt.Errorf("the list of DNS names to add to the serving certificate is empty")
	}

	o.RestConfig, err = o.kubeConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to build kubernetes rest config: %s", err)
	}

	if o.Controller.DisableKubernetesClientRateLimiter {
		log.Info("Disabling Kubernetes client rate limiter.")
		// A negative QPS and Burst indicates that the client should not have a rate limiter.
		// Ref: https://github.com/kubernetes/kubernetes/blob/v1.24.0/staging/src/k8s.io/client-go/rest/config.go#L354-L364
		o.RestConfig.QPS = -1
		o.RestConfig.Burst = -1
	}

	if len(o.TLS.RootCAsCertFile) == 0 {
		log.Info("WARNING: --root-ca-file is not defined which means the root CA will be discovered by the configured issuer. Without a statically defined trust bundle, it will be very difficult to safely rotate the chain used for issuance.")
	} else {
		log.Info("Using root CAs from file: " + o.TLS.RootCAsCertFile)
	}

	if o.CertManager.PreserveCertificateRequests {
		log.Info("WARNING: --preserve-certificate-requests is enabled. Do not enable this option in production, or environments with any non-trivial number of workloads for an extended period of time. Doing so will balloon the resource consumption of ETCD, the API server, and istio-csr, leading to errors and slowdown. This option is intended for debugging purposes only, for limited periods of time.")
	}

	err = o.IstiodCert.Validate()
	if err != nil {
		return err
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
	o.addAdditionalAnnotationsFlags(nfs.FlagSet("additional-annotations"))

	istiodcert.AddFlags(&o.IstiodCert, nfs.FlagSet("istiod-cert"))

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
	fs.Uint32VarP(&o.logLevel,
		"log-level", "v", 1,
		"Log level (1-5).")

	fs.StringVar(&o.logFormat,
		"log-format", "text",
		"log output format: text|json")

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

	fs.IntVar(&o.TLS.ServingCertificateKeySize,
		"serving-certificate-key-size", 2048,
		"Number of bits to use for the server's serving certificate (RSAKeySize).")

	fs.StringVar(&o.TLS.ServingSignatureAlgorithm,
		"serving-signature-algorithm", "RSA",
		"The type of signature algorithm to use when generating private keys. "+
			"Currently only RSA and ECDSA are supported. By default RSA is used.")
}

func (o *Options) addCertManagerFlags(fs *pflag.FlagSet) {
	fs.BoolVarP(&o.CertManager.PreserveCertificateRequests,
		"preserve-certificate-requests", "d", false,
		"If enabled, will preserve created CertificateRequests, rather than "+
			"deleting when they are ready. *WARNING*: do not use in production "+
			"environments as over time requests will consume large amounts of etcd and "+
			"API server resources.")

	fs.StringVarP(&o.CertManager.Namespace,
		"certificate-namespace", "c", "istio-system",
		"Namespace to request certificates.")
	fs.BoolVarP(&o.CertManager.DefaultIssuerEnabled,
		"issuer-enabled", "e", true,
		"Enable the default issuer, the application will not become ready until this issuer is available.")
	fs.StringVarP(&o.CertManager.IssuerRef.Name,
		"issuer-name", "u", "istio-ca",
		"Name of the issuer to sign istio workload certificates.")
	fs.StringVarP(&o.CertManager.IssuerRef.Kind,
		"issuer-kind", "k", "Issuer",
		"Kind of the issuer to sign istio workload certificates.")
	fs.StringVarP(&o.CertManager.IssuerRef.Group,
		"issuer-group", "g", "cert-manager.io",
		"Group of the issuer to sign istio workload certificates.")

	fs.StringVar(&o.CertManager.IssuanceConfigMapName, "runtime-issuance-config-map-name", "",
		"Name of a ConfigMap to watch at runtime for issuer details. If such a ConfigMap is found, overrides issuer-name, issuer-kind and issuer-group")

	fs.StringVar(&o.CertManager.IssuanceConfigMapNamespace, "runtime-issuance-config-map-namespace", "",
		"Namespace for ConfigMap to be watched at runtime for issuer details")
}

func (o *Options) addAdditionalAnnotationsFlags(fs *pflag.FlagSet) {
	fs.StringToStringVar(&o.CertManager.AdditionalAnnotations,
		"certificate-request-additional-annotations", map[string]string{},
		"Additional annotations to include on created CertificateRequests resources.")
}

func (o *Options) addServerFlags(fs *pflag.FlagSet) {
	fs.StringVarP(&o.Server.ServingAddress,
		"serving-address", "a", "0.0.0.0:6443",
		"Address to serve certificates gRPC service.")

	fs.DurationVarP(&o.Server.MaximumClientCertificateDuration,
		"max-client-certificate-duration", "m", time.Hour,
		"Maximum duration a client certificate can be requested and valid for. Will "+
			"override with this value if the requested duration is larger")

	fs.DurationVarP(&o.Server.ClientCertificateDuration,
		"client-cert-duration", "r", 0,
		"Specify the custom duration for client certificates. "+
			"Overrides the requested duration.")

	fs.StringVar(&o.Server.ClusterID, "cluster-id", "Kubernetes",
		"The ID of the istio cluster to verify.")

	fs.BoolVar(&o.Server.Authenticators.EnableClientCert,
		"enable-client-cert-authenticator", false,
		"Enable the client certificate authenticator.")

	fs.StringSliceVar(&o.Server.CATrustedNodeAccounts,
		"ca-trusted-node-accounts", []string{},
		"A list of service accounts that are allowed to use node authentication for CSRs. "+
			"Node authentication allows an identity to create CSRs on behalf of other identities, but only if there is a pod "+
			"running on the same node with that identity. "+
			"This is intended for use with node proxies.",
	)
}

func (o *Options) addControllerFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Controller.LeaderElectionNamespace,
		"leader-election-namespace", "istio-system",
		"Namespace to use for controller leader election.")

	fs.StringVar(&o.Controller.ConfigMapNamespaceSelector,
		"configmap-namespace-selector", "",
		"Selector to filter on namespaces where the controller creates istio-ca-root-cert"+
			" ConfigMap. Supports '=', '==', and '!='.(e.g. -l key1=value1,key2=value2)")

	fs.BoolVar(&o.Controller.DisableKubernetesClientRateLimiter,
		"disable-kubernetes-client-rate-limiter", false,
		"Allows the default client-go rate limiter to be disabled if the Kubernetes API server supports "+
			"[API Priority and Fairness](https://kubernetes.io/docs/concepts/cluster-administration/flow-control/)")
}
