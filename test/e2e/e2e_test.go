package e2e

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/onsi/ginkgo"
	ginkgoconfig "github.com/onsi/ginkgo/config"
	"github.com/onsi/ginkgo/reporters"
	"github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cert-manager/istio-csr/test/e2e/framework/config"
	_ "github.com/cert-manager/istio-csr/test/e2e/suite"
)

func init() {
	config.GetConfig().AddFlags(flag.CommandLine)

	// Turn on verbose by default to get spec names
	ginkgoconfig.DefaultReporterConfig.Verbose = true
	// Turn on EmitSpecProgress to get spec progress (especially on interrupt)
	ginkgoconfig.GinkgoConfig.EmitSpecProgress = true
	// Randomize specs as well as suites
	ginkgoconfig.GinkgoConfig.RandomizeAllSpecs = true

	wait.ForeverTestTimeout = time.Second * 60
}

func TestE2E(t *testing.T) {
	flag.Parse()

	gomega.RegisterFailHandler(ginkgo.Fail)

	junitPath := "../../_artifacts"
	if path := os.Getenv("ARTIFACTS"); path != "" {
		junitPath = path
	}

	junitReporter := reporters.NewJUnitReporter(filepath.Join(
		junitPath,
		"junit-go-e2e.xml",
	))
	ginkgo.RunSpecsWithDefaultAndCustomReporters(t, "cert-manager istio agent e2e suite", []ginkgo.Reporter{junitReporter})
}
