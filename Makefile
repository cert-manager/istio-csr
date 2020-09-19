BINDIR ?= $(CURDIR)/bin
ARCH   ?= amd64

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
	docker build -t localhost:5000/cert-manager-istio-agent:v0.0.1 .
	#docker build -t quay.io/jetstack/cert-manager-istio-agent :v0.0.1 .

clean: ## clean up created files
	rm -rf \
		$(BINDIR)

all: test build docker ## runs test, build and docker

demo: demo_cluster_create demo_image demo_deploy_demo ## create kind cluster and deploy demo

demo_cluster_create: # create demo kind cluster
	./demo/kind-with-registry.sh

demo_image: build image # create agent image and push
	docker push localhost:5000/cert-manager-istio-agent:v0.0.1

demo_deploy_demo: # deploy demo manifests and install istio
	./demo/deploy-demo.sh

