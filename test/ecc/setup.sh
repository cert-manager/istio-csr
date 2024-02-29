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
echo ">> creating root of trust"

echo ">> creating cert-manager issuers"
$KUBECTL_BIN create namespace istio-system || true
$KUBECTL_BIN apply -f "$TEST_DIR/issuers/."

echo ">> waiting for issuers to become ready"
$KUBECTL_BIN get issuers -n istio-system
$KUBECTL_BIN wait --timeout=180s -n istio-system --for=condition=ready issuer istio-root-1
$KUBECTL_BIN get issuers -n istio-system

echo ">> extracting root of trust"
$KUBECTL_BIN get secret -n istio-system istio-root-1 -o jsonpath="{.data['ca\.crt']}" | base64 -d > "$TEST_DIR/ca.pem"

echo ">> creating root of trust secret"
$KUBECTL_BIN create secret generic istio-root-certs --from-file=ca.pem="$TEST_DIR/ca.pem" -n cert-manager || true

echo "======================================"
echo ">> installing istio-csr with roots of trust, using issuer from root-1"

echo ">> installing cert-manager-istio-csr with using ecdsa key type"
echo "$HELM_BIN upgrade -i cert-manager-istio-csr ./deploy/charts/istio-csr -n cert-manager --values $TEST_DIR/values/istio-csr-ecdsa_p${KEY_SIZE}.yaml --wait"

$HELM_BIN upgrade -i cert-manager-istio-csr ./deploy/charts/istio-csr \
  -n cert-manager \
  --values "$TEST_DIR/values/istio-csr-ecdsa_p${KEY_SIZE}.yaml" \
  --set image.repository="$ISTIO_CSR_IMAGE" \
  --set image.tag="$ISTIO_CSR_IMAGE_TAG" \
  --wait

echo ">> installing istio"
$ISTIO_BIN install -y -f "$TEST_DIR/values/istio-ecdsa_p${KEY_SIZE}.yaml"

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

