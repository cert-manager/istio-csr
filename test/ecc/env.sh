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

export ARTIFACTS="${ARTIFACTS:-./_bin/artifacts}"
export ISTIO_CSR_IMAGE="${ISTIO_CSR_IMAGE:-cert-manager.local/cert-manager-istio-csr}"
export ISTIO_CSR_IMAGE_TAG="${ISTIO_CSR_IMAGE_TAG:-canary}"
export KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-istio-ca-ecc}"

export ISTIO_BIN="${ISTIO_BIN:-./_bin/scratch/istioctl-1.20.2}"
export KUBECTL_BIN="${KUBECTL_BIN:-./_bin/tools/kubectl}"
export HELM_BIN="${HELM_BIN:-./_bin/tools/helm}"
export KIND_BIN="${KIND_BIN:-./_bin/tools/kind}"
export JQ_BIN="${JQ_BIN:-./_bin/tools/jq}"
export RED="\e[31m"
export GREEN="\e[32m"
export ENDCOLOR="\e[0m"
