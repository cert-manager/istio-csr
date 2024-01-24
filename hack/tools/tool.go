//go:build tools
// +build tools

package tools

// This file is used to vendor packages we use to build binaries.
// This is the current canonical way with go modules.

import (
	_ "github.com/itchyny/gojq/cmd/gojq"
	_ "github.com/norwoodj/helm-docs/cmd/helm-docs"
	_ "github.com/onsi/ginkgo/v2/ginkgo"
	_ "helm.sh/helm/v3/cmd/helm"
	_ "sigs.k8s.io/kind"
)
