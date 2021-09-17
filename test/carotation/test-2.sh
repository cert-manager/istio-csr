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
echo ">> rotating the CA being used"

echo ">> reinstalling istio-csr with new issuer"
$KUBECTL_BIN delete deploy -n cert-manager cert-manager-istio-csr --wait
$HELM_BIN upgrade -i cert-manager-istio-csr ./deploy/charts/istio-csr -n cert-manager --values $TEST_DIR/values/istio-csr-2.yaml --wait
sleep 5s

echo ">> rotating httpbin pod so it picks up new CA"
POD_NAME=$($KUBECTL_BIN get pod -n sandbox -l app=httpbin -o jsonpath='{.items[0].metadata.name}')
echo ">> current mTLS certificate"
$ISTIO_BIN pc s $POD_NAME -n sandbox -o json | jq -r '.dynamicActiveSecrets[0].secret.tlsCertificate.certificateChain.inlineBytes' | base64 -d | openssl x509 --noout --text | grep Issuer:

$KUBECTL_BIN delete po -n sandbox $POD_NAME --wait --timeout=180s
$KUBECTL_BIN wait -n sandbox --for=condition=ready pod -l app=httpbin --timeout=180s

echo ">> new mTLS certificate"
POD_NAME=$($KUBECTL_BIN get pod -n sandbox -l app=httpbin -o jsonpath='{.items[0].metadata.name}')
$ISTIO_BIN pc s $POD_NAME -n sandbox -o json | jq -r '.dynamicActiveSecrets[0].secret.tlsCertificate.certificateChain.inlineBytes' | base64 -d | openssl x509 --noout --text | grep Issuer:


echo ">> testing mTLS connection between workloads"
POD_NAME=$($KUBECTL_BIN get pod -n sandbox -l app=sleep -o jsonpath='{.items[0].metadata.name}')
$KUBECTL_BIN exec $POD_NAME -c sleep -n sandbox -- curl -sS httpbin:8000/ip
