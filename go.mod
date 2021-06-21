module github.com/cert-manager/istio-csr

go 1.15

require (
	github.com/go-logr/logr v0.4.0
	github.com/jetstack/cert-manager v1.4.0
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.13.0
	github.com/spf13/cobra v1.1.3
	github.com/spf13/pflag v1.0.5
	google.golang.org/grpc v1.38.0
	istio.io/api v0.0.0-20210617183632-a1ac914aead5
	istio.io/istio v0.0.0-20210621105413-9868a6392ce3
	istio.io/pkg v0.0.0-20210618150320-2df9dbfcd1b1
	k8s.io/api v0.21.1
	k8s.io/apimachinery v0.21.1
	k8s.io/cli-runtime v0.21.1
	k8s.io/client-go v0.21.1
	k8s.io/component-base v0.21.1
	k8s.io/klog/v2 v2.8.0
	sigs.k8s.io/controller-runtime v0.9.0
	sigs.k8s.io/kind v0.11.1
)
