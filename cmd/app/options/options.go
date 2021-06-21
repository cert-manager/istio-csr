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
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmversioned "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/jwt"
	"istio.io/istio/pkg/security"
	"istio.io/istio/security/pkg/server/ca/authenticate/kubeauth"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/klogr"
)

// Options is a struct to hold options for cert-manager-istio-csr
type Options struct {
	*AppOptions
	*CertManagerOptions
	*TLSOptions
	*KubeOptions
}

type AppOptions struct {
	logLevel string
	Logr     logr.Logger

	ReadyzPort int
	ReadyzPath string
}

type CertManagerOptions struct {
	issuerName  string
	issuerKind  string
	issuerGroup string

	MaximumClientCertificateDuration time.Duration

	Namespace   string
	PreserveCRs bool
	IssuerRef   cmmeta.ObjectReference
}

type TLSOptions struct {
	RootCACertFile             string
	RootCAConfigMapName        string
	ServingAddress             string
	ServingCertificateDuration time.Duration
	ServingCertificateDNSNames []string

	ClusterID   string
	TrustDomain string
}

type KubeOptions struct {
	kubeConfigFlags *genericclioptions.ConfigFlags

	RestConfig *rest.Config
	KubeClient kubernetes.Interface
	CMClient   cmclient.CertificateRequestInterface
	Auther     security.Authenticator
}

func New() *Options {
	return &Options{
		AppOptions:         new(AppOptions),
		CertManagerOptions: new(CertManagerOptions),
		TLSOptions:         new(TLSOptions),
		KubeOptions:        new(KubeOptions),
	}
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
	if len(o.TLSOptions.ServingCertificateDNSNames) == 0 {
		return fmt.Errorf("the list of DNS names to add to the serving certificate is empty")
	}

	var err error
	o.RestConfig, err = o.kubeConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to build kubernetes rest config: %s", err)
	}

	o.KubeClient, err = kubernetes.NewForConfig(o.RestConfig)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client: %s", err)
	}

	meshcnf := mesh.DefaultMeshConfig()
	meshcnf.TrustDomain = o.TLSOptions.TrustDomain
	o.Auther = kubeauth.NewKubeJWTAuthenticator(mesh.NewFixedWatcher(&meshcnf), o.KubeClient, o.ClusterID, nil, jwt.PolicyThirdParty)

	cmClient, err := cmversioned.NewForConfig(o.RestConfig)
	if err != nil {
		return fmt.Errorf("failed to build cert-manager client: %s", err)
	}

	o.CMClient = cmClient.CertmanagerV1().CertificateRequests(o.Namespace)

	o.IssuerRef = cmmeta.ObjectReference{
		Name:  o.issuerName,
		Kind:  o.issuerKind,
		Group: o.issuerGroup,
	}

	return nil
}

func (o *Options) addFlags(cmd *cobra.Command) {
	var nfs cliflag.NamedFlagSets

	o.AppOptions.addFlags(nfs.FlagSet("App"))
	o.TLSOptions.addFlags(nfs.FlagSet("TLS"))
	o.CertManagerOptions.addFlags(nfs.FlagSet("cert-manager"))
	o.KubeOptions.kubeConfigFlags = genericclioptions.NewConfigFlags(true)
	o.KubeOptions.kubeConfigFlags.AddFlags(nfs.FlagSet("Kubernetes"))

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

func (a *AppOptions) addFlags(fs *pflag.FlagSet) {
	fs.StringVarP(&a.logLevel,
		"log-level", "v", "1",
		"Log level (1-5).")

	fs.IntVar(&a.ReadyzPort,
		"readiness-probe-port", 6060,
		"Port to expose the readiness probe.")

	fs.StringVar(&a.ReadyzPath,
		"readiness-probe-path", "/readyz",
		"HTTP path to expose the readiness probe server.")
}

func (t *TLSOptions) addFlags(fs *pflag.FlagSet) {
	fs.StringVarP(&t.ServingAddress,
		"serving-address", "a", "0.0.0.0:443",
		"Address to serve certificates gRPC service.")

	fs.DurationVarP(&t.ServingCertificateDuration,
		"serving-certificate-duration", "t", time.Hour*24,
		"Certificate duration of serving certificates. Will be renewed after 2/3 of "+
			"the duration.")

	fs.StringSliceVar(&t.ServingCertificateDNSNames,
		"serving-certificate-dns-names", []string{"cert-manager-istio-csr.cert-manager.svc"},
		"A list of DNS names to request for the server's serving certificate which will be "+
			"presented to istio-agents.")

	fs.StringVar(&t.RootCACertFile,
		"root-ca-file", "",
		"File location of a PEM encoded Root CA certificate to be used as root of "+
			"trust for TLS. If empty, the CA returned from the cert-manager issuer will "+
			"be used.")

	fs.StringVar(&t.RootCAConfigMapName,
		"root-ca-configmap-name", "istio-ca-root-cert",
		"The ConfigMap name to store the root CA certificate in each namespace.")

	fs.StringVar(&t.ClusterID, "cluster-id", "Kubernetes",
		"The ID of the istio cluster to verify.")

	fs.StringVar(&t.TrustDomain,
		"trust-domain", "cluster.local",
		"The Istio cluster's trust domain.")
}

func (c *CertManagerOptions) addFlags(fs *pflag.FlagSet) {
	fs.StringVarP(&c.issuerName,
		"issuer-name", "u", "istio-ca",
		"Name of the issuer to sign istio workload certificates.")
	fs.StringVarP(&c.issuerKind,
		"issuer-kind", "k", "Issuer",
		"Kind of the issuer to sign istio workload certificates.")
	fs.StringVarP(&c.issuerGroup,
		"issuer-group", "g", "cert-manager.io",
		"Group of the issuer to sign istio workload certificates.")

	fs.DurationVarP(&c.MaximumClientCertificateDuration,
		"max-client-certificate-duration", "m", time.Hour*24,
		"Maximum duration a client certificate can be requested and valid for. Will "+
			"override with this value if the requested duration is larger")

	fs.BoolVarP(&c.PreserveCRs,
		"preserve-certificate-requests", "d", false,
		"If enabled, will preserve created CertificateRequests, rather than "+
			"deleting when they are ready.")

	fs.StringVarP(&c.Namespace,
		"certificate-namespace", "c", "istio-system",
		"Namespace to request certificates.")
}
