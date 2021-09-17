#!/usr/bin/env bash

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

export K8S_NAMESPACE="${K8S_NAMESPACE:-istio-system}"
export CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-1.4.0}"
export ISTIO_AGENT_IMAGE="${CERT_MANAGER_ISTIO_AGENT_IMAGE:-quay.io/jetstack/cert-manager-istio-csr:canary}"
export KUBECTL_BIN="${KUBECTL_BIN:-./bin/kubectl}"
export HELM_BIN="${HELM_BIN:-./bin/helm}"
export KIND_BIN="${KIND_BIN:-./bin/kind}"
export TEST_DIR="${ROOT_DIR:-./test/carotation}"
export ISTIO_VERSION="${ISTIO_VERSION:-1.10.0}"
export ISTIO_BIN="${ISTIO_BIN:-./bin/istioctl-$ISTIO_VERSION}"
