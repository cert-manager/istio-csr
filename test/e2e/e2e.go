package e2e

import (
	"os"

	. "github.com/onsi/ginkgo"
	"k8s.io/klog/v2"

	"github.com/cert-manager/istio-csr/test/e2e/framework/config"
)

var (
	cfg = config.GetConfig()
)

var _ = SynchronizedBeforeSuite(func() []byte {
	var err error
	cfg.RepoRoot, err = os.Getwd()
	if err != nil {
		klog.Fatal(err)
	}

	if err := cfg.Validate(); err != nil {
		klog.Fatalf("Invalid test config: %s", err)
	}

	return nil
}, func([]byte) {
})

var _ = SynchronizedAfterSuite(func() {},
	func() {
	},
)
