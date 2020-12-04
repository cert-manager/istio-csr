BINDIR ?= $(CURDIR)/bin
ARCH   ?= $(shell go env GOARCH)
ISTIO_VERSION ?= 1.7.3
K8S_VERSION ?= 1.19.4

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	OS := linux
endif
ifeq ($(UNAME_S),Darwin)
	OS := darwin
endif

help:  ## display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: help test build verify image clean all demo docker e2e depend

test: ## test cert-manager-istio-agent
	go test $$(go list ./pkg/... ./cmd/...)

build: ## build cert-manager-istio-agent
	mkdir -p $(BINDIR)
	CGO_ENABLED=0 go build -o ./bin/cert-manager-istio-agent  ./cmd/.

verify: test build ## tests and builds cert-manager-istio-agent

build_image_binary: ## builds image binary
	GOARCH=$(ARCH) GOOS=linux CGO_ENABLED=0 go build -o ./bin/cert-manager-istio-agent-linux  ./cmd/.

image: build_image_binary ## build docker image from binary
	docker build -t quay.io/jetstack/cert-manager-istio-agent:v0.0.1-alpha.0 .

clean: ## clean up created files
	rm -rf \
		$(BINDIR)

all: test build docker ## runs test, build and docker

demo: depend build test build_image_binary ## create kind cluster and deploy demo
	./hack/demo/deploy-demo.sh $(K8S_VERSION)
	$(BINDIR)/kubectl label namespace default istio-injection=enabled

e2e: demo ## build demo cluster and runs end to end tests
	./hack/run-e2e.sh
	./hack/demo/destroy-demo.sh

depend: $(BINDIR)/istioctl $(BINDIR)/ginkgo $(BINDIR)/kubectl $(BINDIR)/kind

$(BINDIR)/istioctl:
	mkdir -p $(BINDIR)
	curl -L https://istio.io/downloadIstio | ISTIO_VERSION=$(ISTIO_VERSION) sh -
	mv istio-$(ISTIO_VERSION)/bin/istioctl $(BINDIR)/.
	rm -r istio-$(ISTIO_VERSION)

$(BINDIR)/ginkgo:
	go build -o $(BINDIR)/ginkgo github.com/onsi/ginkgo/ginkgo

$(BINDIR)/kind:
	go build -o $(BINDIR)/kind sigs.k8s.io/kind

$(BINDIR)/kubectl:
	curl -o ./bin/kubectl -LO "https://storage.googleapis.com/kubernetes-release/release/$(shell curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/$(OS)/$(ARCH)/kubectl"
	chmod +x ./bin/kubectl
