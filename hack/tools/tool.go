//go:build tools
// +build tools

package tools

// This file is used to vendor packages we use to build binaries.
// This is the current canonical way with go modules.

import (
	_ "github.com/itchyny/gojq/cmd/gojq"
	_ "github.com/onsi/ginkgo/ginkgo"
	_ "sigs.k8s.io/kind"
)
