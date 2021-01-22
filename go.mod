module github.com/cert-manager/istio-csr

go 1.15

require (
	github.com/go-logr/logr v0.3.0
	github.com/jetstack/cert-manager v1.1.0
	github.com/onsi/ginkgo v1.14.1
	github.com/onsi/gomega v1.10.4
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/pflag v1.0.5
	google.golang.org/grpc v1.33.2
	istio.io/api v0.0.0-20200903133517-d3db41cca51a
	istio.io/istio v0.0.0-20200903155103-cf61d6c8ad52
	istio.io/pkg v0.0.0-20200807223740-7c8bbc23c476
	k8s.io/api v0.20.1
	k8s.io/apimachinery v0.20.1
	k8s.io/cli-runtime v0.20.1
	k8s.io/client-go v0.20.1
	k8s.io/component-base v0.20.1
	k8s.io/klog/v2 v2.4.0
	sigs.k8s.io/controller-runtime v0.8.0
	sigs.k8s.io/kind v0.9.0
)
