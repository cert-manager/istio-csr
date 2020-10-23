BINDIR ?= $(CURDIR)/bin
ARCH   ?= amd64
ISTIO_VERSION ?= 1.7.3
DEMO_MANIFEST_URL ?= https://raw.githubusercontent.com/istio/istio/master/samples/bookinfo/platform/kube/bookinfo.yaml

help:  ## display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: help build docker all clean

test: ## test cert-manager-istio-agent
	go test ./...

build: ## build cert-manager-istio-agent
	mkdir -p $(BINDIR)
	CGO_ENABLED=0 go build -o ./bin/cert-manager-istio-agent  ./cmd/.

verify: test build ## tests and builds cert-manager-istio-agent

image: ## build docker image
	GOARCH=$(ARCH) GOOS=linux CGO_ENABLED=0 go build -o ./bin/cert-manager-istio-agent-linux  ./cmd/.
	docker build -t quay.io/jetstack/cert-manager-istio-agent :v0.0.1 .

clean: ## clean up created files
	rm -rf \
		$(BINDIR)

all: test build docker ## runs test, build and docker

demo: depend build test ## create kind cluster and deploy demo
	./hack/demo/deploy-demo.sh
	kubectl label namespace default istio-injection=enabled

e2e: demo ## build demo cluster and runs end to end tests
	./hack/run-e2e.sh

depend: $(BINDIR)/istioctl $(BINDIR)/ginko

$(BINDIR)/istioctl:
	mkdir -p $(BINDIR)
	curl -L https://istio.io/downloadIstio | ISTIO_VERSION=$(ISTIO_VERSION) sh -
	mv istio-$(ISTIO_VERSION)/bin/istioctl $(BINDIR)/.
	rm -r istio-$(ISTIO_VERSION)

$(BINDIR)/ginko:
	go build -o $(BINDIR)/ginkgo github.com/onsi/ginkgo/ginkgo
