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

	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
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
