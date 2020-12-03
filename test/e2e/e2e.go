package e2e

import (
	"os"

	. "github.com/onsi/ginkgo"
	log "github.com/sirupsen/logrus"

	"github.com/cert-manager/istio-csr/test/e2e/framework/config"
)

var (
	cfg = config.GetConfig()
)

var _ = SynchronizedBeforeSuite(func() []byte {
	var err error
	cfg.RepoRoot, err = os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid test config: %s", err)
	}

	return nil
}, func([]byte) {
})

var _ = SynchronizedAfterSuite(func() {},
	func() {
	},
)
