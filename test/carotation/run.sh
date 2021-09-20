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


source ./test/carotation/env.sh


# Ensure we always clean up after ourselves.
cleanup() {
  $TEST_DIR/cleanup-1.sh
}
trap cleanup EXIT

echo "======================================"
echo ">> running CA rotation test"

$TEST_DIR/setup-1.sh

$TEST_DIR/setup-2.sh

$TEST_DIR/setup-3.sh

$TEST_DIR/test-1.sh

$TEST_DIR/test-2.sh
