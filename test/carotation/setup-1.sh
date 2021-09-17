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

echo ">> building istio-csr binary..."
GOARCH=$(go env GOARCH) GOOS=linux CGO_ENABLED=0 go build -o ./bin/istio-csr-linux ./cmd/.

echo ">> building docker image..."
docker build -t $ISTIO_AGENT_IMAGE .

echo ">> deleting any existing kind cluster..."
$KIND_BIN delete cluster --name istio-ca-rotation

echo ">> pre-creating 'kind' docker network to avoid networking issues in CI"
# When running in our CI environment the Docker network's subnet choice will cause issues with routing
# This works this around till we have a way to properly patch this.
docker network create --driver=bridge --subnet=192.168.0.0/16 --gateway 192.168.0.1 kind || true
# Sleep for 2s to avoid any races between docker's network subcommand and 'kind create'
sleep 2

echo ">> creating kind cluster..."
$KIND_BIN create cluster --name istio-ca-rotation

echo ">> loading docker image..."
$KIND_BIN load docker-image $ISTIO_AGENT_IMAGE --name istio-ca-rotation

echo ">> installing cert-manager"
$HELM_BIN repo add jetstack https://charts.jetstack.io --force-update
$HELM_BIN upgrade -i -n cert-manager cert-manager jetstack/cert-manager --set installCRDs=true --wait --create-namespace --set global.logLevel=2
