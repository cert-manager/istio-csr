# Copyright 2021 The cert-manager Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

BINDIR ?= $(CURDIR)/bin
ARCH   ?= $(shell go env GOARCH)
ISTIO_VERSION ?= 1.10.0
K8S_VERSION ?= 1.21.1
HELM_VERSION ?= 3.4.1
IMAGE_PLATFORMS ?= linux/amd64,linux/arm64,linux/arm/v7,linux/ppc64le

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	OS := linux
endif
ifeq ($(UNAME_S),Darwin)
	OS := darwin
endif

.PHONY: help
help:  ## display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: test
test: lint ## test cert-manager-istio-csr
	go test $$(go list ./pkg/... ./cmd/...)

.PHONY: lint
lint: boilerplate vet ## run code linting tests

.PHONY: vet
vet:
	go vet -v ./...

.PHONY: boilerplate
boilerplate:
	./hack/verify-boilerplate.sh

.PHONY: build
build: ## build cert-manager-istio-csr
	mkdir -p $(BINDIR)
	CGO_ENABLED=0 go build -v -o ./bin/cert-manager-istio-csr  ./cmd/.

.PHONY: verify
verify: test build ## tests and builds cert-manager-istio-csr

# image will only build and store the image locally, targeted in OCI format.
# To actually push an image to the public repo, replace the `--output` flag and
# arguments to `--push`.
.PHONY: image
image: ## build docker image targeting all supported platforms
	docker buildx build --platform=$(IMAGE_PLATFORMS) -t quay.io/jetstack/cert-manager-istio-csr:v0.2.1 --output type=oci,dest=./bin/cert-manager-istio-csr-oci .

.PHONY: clean
clean: ## clean up created files
	rm -rf \
		$(BINDIR) \
		_artifacts

.PHONY: all
all: test build docker ## runs test, build and docker

.PHONY: demo
demo: depend build test ## create kind cluster and deploy demo
	./hack/demo/deploy-demo.sh $(K8S_VERSION) $(ISTIO_VERSION)
	$(BINDIR)/kubectl label namespace default istio-injection=enabled

.PHONY: e2e
e2e: demo ## build demo cluster and runs end to end tests
	./hack/run-e2e.sh
	./hack/demo/destroy-demo.sh

.PHONY: carotation
carotation: depend ## run ca rotation test
	./test/carotation/run.sh

.PHONY: depend
depend: $(BINDIR)/istioctl-$(ISTIO_VERSION) $(BINDIR)/ginkgo $(BINDIR)/kubectl $(BINDIR)/kind $(BINDIR)/helm $(BINDIR)/jq

$(BINDIR)/istioctl-$(ISTIO_VERSION):
	mkdir -p $(BINDIR)
	curl -L https://istio.io/downloadIstio | ISTIO_VERSION=$(ISTIO_VERSION) sh -
	mv istio-$(ISTIO_VERSION)/bin/istioctl $(BINDIR)/istioctl-$(ISTIO_VERSION)-tmp
	rm -r istio-$(ISTIO_VERSION)
	mv $(BINDIR)/istioctl-$(ISTIO_VERSION)-tmp $(BINDIR)/istioctl-$(ISTIO_VERSION)

$(BINDIR)/ginkgo:
	go build -o $(BINDIR)/ginkgo github.com/onsi/ginkgo/ginkgo

$(BINDIR)/kind:
	go build -o $(BINDIR)/kind sigs.k8s.io/kind

$(BINDIR)/helm:
	curl -o $(BINDIR)/helm.tar.gz -LO "https://get.helm.sh/helm-v$(HELM_VERSION)-$(OS)-$(ARCH).tar.gz"
	tar -C $(BINDIR) -xzf $(BINDIR)/helm.tar.gz
	cp $(BINDIR)/$(OS)-$(ARCH)/helm $(BINDIR)/helm
	rm -r $(BINDIR)/$(OS)-$(ARCH) $(BINDIR)/helm.tar.gz

$(BINDIR)/kubectl:
	curl -o ./bin/kubectl -LO "https://storage.googleapis.com/kubernetes-release/release/$(shell curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/$(OS)/$(ARCH)/kubectl"
	chmod +x ./bin/kubectl

$(BINDIR)/jq:
	go build -o $(BINDIR)/jq github.com/itchyny/gojq/cmd/gojq
