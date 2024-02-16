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

.PHONY: test-ecc
## ecc test
## @category Testing
test-ecc: kind_cluster_name := "istio-csr-ecc"
test-ecc: e2e-setup-cert-manager oci-load-manager | $(bin_dir)/scratch/istioctl-$(ISTIO_VERSION) $(NEEDS_KUBECTL) $(NEEDS_HELM) $(NEEDS_KIND) $(NEEDS_GOJQ)
	$(eval oci_image_tar := $(bin_dir)/scratch/image/oci-layout-manager.$(oci_manager_image_tag).docker.tar)

	ARTIFACTS=$(ARTIFACTS) \
	ISTIO_CSR_IMAGE=$(oci_manager_image_name_development) \
	ISTIO_CSR_IMAGE_TAR=$(oci_image_tar) \
	ISTIO_CSR_IMAGE_TAG=$(oci_manager_image_tag) \
	KIND_CLUSTER_NAME=$(kind_cluster_name) \
	ISTIO_BIN=$(bin_dir)/scratch/istioctl-$(ISTIO_VERSION) \
	KUBECTL_BIN=$(KUBECTL) \
	HELM_BIN=$(HELM) \
	KIND_BIN=$(KIND) \
	JQ_BIN=$(GOJQ) \
		./test/ecc/run.sh
