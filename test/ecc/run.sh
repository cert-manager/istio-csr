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

TEST_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ISTIO_CSR_SERVING_CERTFILE="${TEST_DIR}"/istio-csr-serving.pems

export TEST_DIR
# This will contain the signed certificate of "istio-csr-serving" CertificateRequests to run assertions against
export ISTIO_CSR_SERVING_CERTFILE
source "$TEST_DIR/env.sh"

# Ensure we always clean up after ourselves.
cleanup() {
  "$TEST_DIR/cleanup.sh"
}
trap cleanup EXIT

echo "======================================"
echo ">> running full ECC 256 and 384 support"

export KEY_SIZE="256"
"$TEST_DIR/setup.sh"
"$TEST_DIR/test.sh"

"$TEST_DIR/reset-istio-csr.sh"
export KEY_SIZE="384"
"$TEST_DIR/setup.sh"
"$TEST_DIR/test.sh"

