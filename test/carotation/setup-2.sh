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
echo ">> creating 2 roots of trust"

echo ">> creating cert-manager issuers"
$KUBECTL_BIN create namespace istio-system
$KUBECTL_BIN apply -f $TEST_DIR/issuers/.

echo ">> waiting for issuers to become ready"
$KUBECTL_BIN get issuers -n istio-system
$KUBECTL_BIN wait -n istio-system --for=condition=ready issuer istio-root-1
$KUBECTL_BIN wait -n istio-system --for=condition=ready issuer istio-root-2
$KUBECTL_BIN wait -n istio-system --for=condition=ready issuer istio-int-1
$KUBECTL_BIN wait -n istio-system --for=condition=ready issuer istio-int-2
$KUBECTL_BIN get issuers -n istio-system

echo ">> extracting roots of trust"
$KUBECTL_BIN get secret -n istio-system istio-root-1 -o jsonpath="{.data['ca\.crt']}" | base64 -d
$KUBECTL_BIN get secret -n istio-system istio-root-1 -o jsonpath="{.data['ca\.crt']}" | base64 -d > $TEST_DIR/ca.pem
$KUBECTL_BIN get secret -n istio-system istio-root-2 -o jsonpath="{.data['ca\.crt']}" | base64 -d
$KUBECTL_BIN get secret -n istio-system istio-root-2 -o jsonpath="{.data['ca\.crt']}" | base64 -d >> $TEST_DIR/ca.pem

echo ">> creating roots of trust secret"
cat $TEST_DIR/ca.pem
$KUBECTL_BIN create secret generic istio-root-certs --from-file=ca.pem=$TEST_DIR/ca.pem -n cert-manager
