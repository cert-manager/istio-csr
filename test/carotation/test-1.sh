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
echo ">> installing workloads and testing connectivity"

echo ">> installing workloads"
$KUBECTL_BIN apply -f $TEST_DIR/workloads --wait --timeout=180s
$KUBECTL_BIN wait -n sandbox --for=condition=ready pod -l app=sleep --timeout=180s
$KUBECTL_BIN wait -n sandbox --for=condition=ready pod -l app=httpbin --timeout=180s

echo ">> testing mTLS connection between workloads"
POD_NAME=$($KUBECTL_BIN get pod -n sandbox -l app=sleep -o jsonpath='{.items[0].metadata.name}')
$KUBECTL_BIN exec $POD_NAME -c sleep -n sandbox -- curl -sS httpbin:8000/ip
