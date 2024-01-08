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

set -o nounset
set -o errexit
set -o pipefail

echo "======================================"
echo ">> setting up CA rotation test cluster"

echo ">> deleting any existing kind cluster..."
$KIND_BIN delete cluster --name istio-ca-rotation

echo ">> creating kind cluster..."
$KIND_BIN create cluster --name istio-ca-rotation

echo ">> loading docker image..."
$KIND_BIN load image-archive $ISTIO_CSR_IMAGE_TAR --name istio-ca-rotation

echo ">> installing cert-manager"
$HELM_BIN repo add jetstack https://charts.jetstack.io --force-update
$HELM_BIN upgrade -i -n cert-manager cert-manager jetstack/cert-manager --set installCRDs=true --wait --create-namespace --set global.logLevel=2
