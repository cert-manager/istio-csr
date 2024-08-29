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

package config

import (
	"errors"
	"flag"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

type Config struct {
	KubeConfigPath string
	KubectlPath    string

	IssuerRef cmmeta.ObjectReference

	IssuanceConfigMapName      string
	IssuanceConfigMapNamespace string

	IstioctlPath string

	AmbientEnabled bool
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
	fs.StringVar(&c.KubeConfigPath, "kubeconfig-path", "", "path to Kubeconfig")
	fs.StringVar(&c.KubectlPath, "kubectl-path", "", "path to Kubectl binary")

	fs.StringVar(&c.IssuanceConfigMapName, "runtime-issuance-config-map-name", "runtime-config-map", "Name of runtime issuance ConfigMap")
	fs.StringVar(&c.IssuanceConfigMapNamespace, "runtime-issuance-config-map-namespace", "cert-manager", "Namespace for runtime issuance ConfigMap")

	fs.StringVar(&c.IstioctlPath, "istioctl-path", "", "path to istioctl binary")
	fs.BoolVar(&c.AmbientEnabled, "ambient-enabled", false, "is ambient data plane enabled")
}

func (c *Config) Validate() error {
	var errs []error

	if c.KubeConfigPath == "" {
		errs = append(errs, errors.New("--kubeconfig-path not set"))
	}

	if c.KubectlPath == "" {
		errs = append(errs, errors.New("--kubectl-path not set"))
	}

	if c.IstioctlPath == "" {
		errs = append(errs, errors.New("--istioctl-path not set"))
	}

	return errors.Join(errs...)
}
