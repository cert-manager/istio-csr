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
echo ">> resetting Istio + istio-csr for another test"

echo ">> $HELM_BIN uninstall cert-manager-istio-csr -n cert-manager"
$HELM_BIN uninstall cert-manager-istio-csr -n cert-manager


echo ">> resetting Istio for another test"
echo ">> $ISTIO_BIN uninstall -y -f \"$TEST_DIR/values/istio-ecdsa_p${KEY_SIZE}.yaml\""

$ISTIO_BIN uninstall -y --purge -f "$TEST_DIR/values/istio-ecdsa_p${KEY_SIZE}.yaml"

$KUBECTL_BIN delete mutatingwebhookconfigurations istio-revision-tag-default
rm -f "${ISTIO_CSR_SERVING_CERTFILE}"
