package config

import (
	"errors"
	"flag"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
)

type Config struct {
	KubeConfigPath string
	RepoRoot       string

	IssuerRef cmmeta.ObjectReference
}

var (
	sharedConfig = &Config{}
)

func SetConfig(config *Config) {
	sharedConfig = config
}

func GetConfig() *Config {
	return sharedConfig
}

func (c *Config) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.IssuerRef.Name, "issuer-name", "istio-ca", "issuer name to use for e2e test")
	fs.StringVar(&c.IssuerRef.Kind, "issuer-kind ", "Issuer", "issuer kind to use for e2e test")
	fs.StringVar(&c.IssuerRef.Group, "issuer-group ", "cert-manager.io", "issuer Group to use for e2e test")
	fs.StringVar(&c.KubeConfigPath, "kubeconfig", "", "path to Kubeconfig")
}

func (c *Config) Validate() error {
	var errs []error

	if c.KubeConfigPath == "" {
		errs = append(errs, errors.New("--kubeconfig not set"))
	}

	if c.RepoRoot == "" {
		errs = append(errs, errors.New("repo root not defined"))
	}

	return utilerrors.NewAggregate(errs)
}
