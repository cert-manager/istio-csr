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
echo ">> installing istio-csr with roots of trust, using issuer from root-1"

echo ">> installing cert-manager-istio-csr with first root"
echo "$HELM_BIN upgrade -i cert-manager-istio-csr ./deploy/charts/istio-csr -n cert-manager --values $TEST_DIR/values/istio-csr-1.yaml --wait"
$HELM_BIN upgrade -i cert-manager-istio-csr ./deploy/charts/istio-csr -n cert-manager --values $TEST_DIR/values/istio-csr-1.yaml --wait

echo ">> installing istio"
$ISTIO_BIN install -y -f $TEST_DIR/values/istio.yaml

echo ">> enforcing mTLS everywhere"
$KUBECTL_BIN apply -n istio-system -f - <<EOF
apiVersion: "security.istio.io/v1beta1"
kind: "PeerAuthentication"
metadata:
  name: "default"
spec:
  mtls:
    mode: STRICT
EOF
