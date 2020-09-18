package options

import (
	"fmt"
	"os"
	"time"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmversioned "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned/typed/certmanager/v1"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"istio.io/istio/pkg/jwt"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/security/pkg/server/ca/authenticate"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	_ "k8s.io/client-go/plugin/pkg/client/auth/openstack"
	cliflag "k8s.io/component-base/cli/flag"
)

// Options is a struct to hold options for cert-manager-istio-agent
type Options struct {
	logLevel string

	issuerName  string
	issuerKind  string
	issuerGroup string
	Namespace   string

	kubeConfigFlags *genericclioptions.ConfigFlags

	Logr *logrus.Entry

	ServingCertificateTTL time.Duration
	ServingAddress        string

	IssuerRef cmmeta.ObjectReference

	CMClient   cmclient.CertificateRequestInterface
	KubeClient kubernetes.Interface
	Auther     authenticate.Authenticator
}

func (o *Options) Prepare(cmd *cobra.Command) *Options {
	o.addFlags(cmd)
	return o
}

func (o *Options) Complete() error {
	logLevel, err := logrus.ParseLevel(o.logLevel)
	if err != nil {
		return fmt.Errorf("failed to parse --log-level %q: %s",
			o.logLevel, err)
	}

	logr := logrus.New()
	logr.SetOutput(os.Stdout)
	logr.SetLevel(logLevel)
	o.Logr = logrus.NewEntry(logr)

	restConfig, err := o.kubeConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to build kubernetes rest config: %s", err)
	}

	o.KubeClient, err = kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to build kubernetes client: %s", err)
	}

	o.Auther = authenticate.NewKubeJWTAuthenticator(o.KubeClient, "Kubernetes", nil, spiffe.GetTrustDomain(), jwt.PolicyThirdParty)

	cmClient, err := cmversioned.NewForConfig(restConfig)
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

	o.addAppFlags(nfs.FlagSet("App"))
	o.addCertManagerFlags(nfs.FlagSet("cert-manager"))
	o.kubeConfigFlags = genericclioptions.NewConfigFlags(true)
	o.kubeConfigFlags.AddFlags(nfs.FlagSet("Kubernetes"))

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
		"log-level", "v", "info",
		"Log level (debug, info, warn, error, fatal, panic).")

	fs.StringVarP(&o.ServingAddress,
		"serving-address", "a", "0.0.0.0:443",
		"Address to serve certificates gRPC service.")

	fs.DurationVarP(&o.ServingCertificateTTL,
		"serving-certificate-ttl", "t", time.Hour*24,
		"TTL duration of serving certificates. Will be renewed after 2/3 of the "+
			"duration.")
}

func (o *Options) addCertManagerFlags(fs *pflag.FlagSet) {
	fs.StringVarP(&o.issuerName,
		"issuer-name", "u", "istio-ca",
		"Name of the issuer to sign istio workload certificates.")
	fs.StringVarP(&o.issuerKind,
		"issuer-kind", "k", "Issuer",
		"Kind of the issuer to sign istio workload certificates.")
	fs.StringVarP(&o.issuerGroup,
		"issuer-group", "g", "cert-manager.io",
		"Group of the issuer to sign istio workload certificates.")

	fs.StringVarP(&o.Namespace,
		"certificate-namespace", "c", "istio-system",
		"Namespace to request certificates.")
}
