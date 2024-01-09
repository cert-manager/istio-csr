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

repo_name := github.com/cert-manager/istio-csr

kind_cluster_name := istio-csr
kind_cluster_config := $(bin_dir)/scratch/kind_cluster.yaml

build_names := manager

go_manager_main_dir := ./cmd
go_manager_mod_dir := .
go_manager_ldflags := -X $(repo_name)/internal/version.AppVersion=$(VERSION) -X $(repo_name)/internal/version.GitCommit=$(GITCOMMIT)
oci_manager_base_image_flavor := static
oci_manager_image_name := quay.io/jetstack/cert-manager-istio-csr
oci_manager_image_tag := $(VERSION)
oci_manager_image_name_development := cert-manager.local/cert-manager-istio-csr

deploy_name := istio-csr
deploy_namespace := cert-manager

helm_chart_source_dir := deploy/charts/istio-csr
helm_chart_name := cert-manager-istio-csr
helm_chart_version := $(VERSION)
define helm_values_mutation_function
$(YQ) \
	'( .image.repository = "$(oci_manager_image_name)" ) | \
	( .image.tag = "$(oci_manager_image_tag)" )' \
	$1 --inplace
endef

mages_amd64 ?=
images_arm64 ?=

images_amd64 += docker.io/kong/httpbin:0.1.0@sha256:9d65a5b1955d2466762f53ea50eebae76be9dc7e277217cd8fb9a24b004154f4
images_arm64 += docker.io/kong/httpbin:0.1.0@sha256:c546c8b06c542b615f053b577707cb72ddc875a0731d56d0ffaf840f767322ad

images_amd64 += quay.io/curl/curl:8.5.0@sha256:f60b4d978aad8920d603df74bdd430b3ebe4895d9e06bc16125f897b168a699b
images_arm64 += quay.io/curl/curl:8.5.0@sha256:a96e5f0e17b6e9699a76ce9f67a1412aec37fde5d881ed382f0295b97395e2ee
