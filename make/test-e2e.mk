# Copyright 2023 The cert-manager Authors.
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

ISTIO_VERSION ?= 1.20.2

$(bin_dir)/scratch/istioctl-$(ISTIO_VERSION): | $(bin_dir)/scratch/
	curl -L https://istio.io/downloadIstio | ISTIO_VERSION=$(ISTIO_VERSION) sh -
	mv istio-$(ISTIO_VERSION)/bin/istioctl $(bin_dir)/scratch/istioctl-$(ISTIO_VERSION)
	rm -r istio-$(ISTIO_VERSION)

.PHONY: e2e-setup-cert-manager
e2e-setup-cert-manager: | kind-cluster $(NEEDS_HELM) $(NEEDS_KUBECTL)
	$(HELM) upgrade \
		--install \
		--create-namespace \
		--wait \
		--version $(quay.io/jetstack/cert-manager-controller.TAG) \
		--namespace cert-manager \
		--repo https://charts.jetstack.io \
		--set installCRDs=true \
		--set image.repository=$(quay.io/jetstack/cert-manager-controller.REPO) \
		--set image.tag=$(quay.io/jetstack/cert-manager-controller.TAG) \
		--set image.pullPolicy=Never \
		--set cainjector.image.repository=$(quay.io/jetstack/cert-manager-cainjector.REPO) \
		--set cainjector.image.tag=$(quay.io/jetstack/cert-manager-cainjector.TAG) \
		--set cainjector.image.pullPolicy=Never \
		--set webhook.image.repository=$(quay.io/jetstack/cert-manager-webhook.REPO) \
		--set webhook.image.tag=$(quay.io/jetstack/cert-manager-webhook.TAG) \
		--set webhook.image.pullPolicy=Never \
		--set startupapicheck.image.repository=$(quay.io/jetstack/cert-manager-startupapicheck.REPO) \
		--set startupapicheck.image.tag=$(quay.io/jetstack/cert-manager-startupapicheck.TAG) \
		--set startupapicheck.image.pullPolicy=Never \
		cert-manager cert-manager >/dev/null

.PHONY: e2e-create-cert-manager-istio-resources
e2e-create-cert-manager-istio-resources: | kind-cluster e2e-setup-cert-manager $(NEEDS_KUBECTL)
	$(KUBECTL) create namespace istio-system || true
	$(KUBECTL) -n istio-system apply --server-side -f ./make/config/cert-manager-bootstrap-resources.yaml

.PHONY: e2e-create-cert-manager-istio-pure-runtime-resources
e2e-create-cert-manager-istio-pure-runtime-resources: | kind-cluster e2e-setup-cert-manager $(NEEDS_KUBECTL)
	$(KUBECTL) apply -f test/e2e-pure-runtime/initial-manifests/configmap.yaml

is_e2e_test=

# The "install" target can be run on its own with any currently active cluster,
# we can't use any other cluster then a target containing "test-e2e" is run.
# When a "test-e2e*" target is run, the currently active cluster must be the kind
# cluster created by the "kind-cluster" target.
ifeq ($(findstring test-e2e,$(MAKECMDGOALS)),test-e2e)
is_e2e_test = yes
endif

ifeq ($(findstring test-e2e-pure-runtime,$(MAKECMDGOALS)),test-e2e-pure-runtime)
is_e2e_test = yes
endif

ifdef is_e2e_test
install: kind-cluster oci-load-manager e2e-create-cert-manager-istio-resources
endif

.PHONY: e2e-setup-istio
e2e-setup-istio: | kind-cluster install $(NEEDS_KUBECTL) $(bin_dir)/scratch/istioctl-$(ISTIO_VERSION)
	$(bin_dir)/scratch/istioctl-$(ISTIO_VERSION) install -y -f ./make/config/istio/istio-config-$(ISTIO_VERSION).yaml
	$(KUBECTL) -n istio-system apply --server-side -f ./make/config/peer-authentication.yaml

E2E_RUNTIME_CONFIG_MAP_NAME ?= runtime-config-map
E2E_FOCUS ?=

test-e2e-deps: INSTALL_OPTIONS :=
test-e2e-deps: INSTALL_OPTIONS += --set image.repository=$(oci_manager_image_name_development)
test-e2e-deps: INSTALL_OPTIONS += --set app.runtimeConfiguration.name=$(E2E_RUNTIME_CONFIG_MAP_NAME)
test-e2e-deps: INSTALL_OPTIONS += --set app.logFormat=json
test-e2e-deps: INSTALL_OPTIONS += --set app.controller.disableKubernetesClientRateLimiter=true
test-e2e-deps: INSTALL_OPTIONS += --set app.server.authenticators.enableClientCert=true
test-e2e-deps: INSTALL_OPTIONS += -f ./make/config/istio-csr-values.yaml
test-e2e-deps: e2e-setup-cert-manager
test-e2e-deps: e2e-create-cert-manager-istio-resources
test-e2e-deps: install
test-e2e-deps: e2e-setup-istio

CI ?=
EXTRA_GINKGO_FLAGS :=

# In Prow, the CI environment variable is set to "true"
# See https://docs.prow.k8s.io/docs/jobs/#job-environment-variables
ifeq ($(CI),true)
EXTRA_GINKGO_FLAGS += --no-color
endif

.PHONY: test-e2e
## e2e end-to-end tests
## @category Testing
test-e2e: test-e2e-deps | kind-cluster $(NEEDS_GINKGO) $(NEEDS_KUBECTL)
	$(GINKGO) \
		--output-dir=$(ARTIFACTS) \
		--focus="$(E2E_FOCUS)" \
		--junit-report=junit-go-e2e.xml \
		$(EXTRA_GINKGO_FLAGS) \
		./test/e2e/ \
		-ldflags $(go_manager_ldflags) \
		-- \
		--istioctl-path $(CURDIR)/$(bin_dir)/scratch/istioctl-$(ISTIO_VERSION) \
		--kubeconfig-path $(CURDIR)/$(kind_kubeconfig) \
		--kubectl-path $(KUBECTL) \
		--runtime-issuance-config-map-name=$(E2E_RUNTIME_CONFIG_MAP_NAME)

test-e2e-pure-runtime-deps: INSTALL_OPTIONS :=
test-e2e-pure-runtime-deps: INSTALL_OPTIONS += --set image.repository=$(oci_manager_image_name_development)
test-e2e-pure-runtime-deps: INSTALL_OPTIONS += --set app.runtimeConfiguration.name=$(E2E_RUNTIME_CONFIG_MAP_NAME)
test-e2e-pure-runtime-deps: INSTALL_OPTIONS += -f ./make/config/istio-csr-pure-runtime-values.yaml
test-e2e-pure-runtime-deps: e2e-setup-cert-manager
test-e2e-pure-runtime-deps: e2e-create-cert-manager-istio-resources
test-e2e-pure-runtime-deps: e2e-create-cert-manager-istio-pure-runtime-resources
test-e2e-pure-runtime-deps: install
test-e2e-pure-runtime-deps: e2e-setup-istio

# "Pure" runtime configuration e2e tests require different installation values
.PHONY: test-e2e-pure-runtime
test-e2e-pure-runtime: test-e2e-pure-runtime-deps | kind-cluster $(NEEDS_GINKGO) $(NEEDS_KUBECTL)
	$(GINKGO) \
		--output-dir=$(ARTIFACTS) \
		--focus="$(E2E_FOCUS)" \
		--junit-report=junit-go-e2e.xml \
		$(EXTRA_GINKGO_FLAGS) \
		./test/e2e-pure-runtime/ \
		-ldflags $(go_manager_ldflags) \
		-- \
		--istioctl-path $(CURDIR)/$(bin_dir)/scratch/istioctl-$(ISTIO_VERSION) \
		--kubeconfig-path $(CURDIR)/$(kind_kubeconfig) \
		--kubectl-path $(KUBECTL) \
		--runtime-issuance-config-map-name=$(E2E_RUNTIME_CONFIG_MAP_NAME)
