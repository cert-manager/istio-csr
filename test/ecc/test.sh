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

echo "======================================"
echo ">> installing workloads and testing connectivity"

echo ">> installing workloads"
$KUBECTL_BIN apply -f "$TEST_DIR/workloads" --wait --timeout=180s
$KUBECTL_BIN wait -n sandbox --for=condition=ready pod -l app=sleep --timeout=180s
$KUBECTL_BIN wait -n sandbox --for=condition=ready pod -l app=httpbin --timeout=180s

echo ">> testing mTLS connection between workloads"
POD_NAME=$($KUBECTL_BIN get pod -n sandbox -l app=sleep -o jsonpath='{.items[0].metadata.name}')
$KUBECTL_BIN exec "$POD_NAME" -c sleep -n sandbox -- curl -sS httpbin:8000/ip

echo "Ensuring the workload certificates are of the right type"
set -x

ISTIOD_KEY_ALGORITHM=$($KUBECTL_BIN get certificate -n istio-system istiod -o jsonpath='{.spec.privateKey.algorithm}')
echo "Ensuring Istiod certificate key algorithm is ECDSA.."
if ! [[ "${ISTIOD_KEY_ALGORITHM}" == "ECDSA" ]]; then
  echo -e "${RED} ✗ Wrong key type, got ${ISTIOD_KEY_ALGORITHM} expected ECDSA ${ENDCOLOR}"
  exit 1
fi
echo -e "${GREEN} ✓ Success ${ENDCOLOR}"

echo "Ensuring Istiod certificate key size is ${KEY_SIZE}"
ISTIOD_KEY_SIZE=$($KUBECTL_BIN get certificate -n istio-system istiod -o jsonpath='{.spec.privateKey.size}')
if ! [[ "${ISTIOD_KEY_SIZE}" == "${KEY_SIZE}" ]]; then 
  echo -e "${RED} ✗ Wrong key size, got ${ISTIOD_KEY_SIZE} expected ${KEY_SIZE} ${ENDCOLOR}"
  exit 1
fi

echo -e "${GREEN} ✓ Success ${ENDCOLOR} "

echo "Getting all 'istio-csr-serving' certificates"
ISTIO_CSR_SERVING_CERTFILE="${TEST_DIR}"/istio-csr-serving.pems

$KUBECTL_BIN  -n istio-system  get cr -n istio-system \
  -o=jsonpath='{.items[?(@.metadata.annotations.istio\.cert-manager\.io/identities=="istio-csr-serving")].status.certificate}' \
 | xargs -n 1 echo -e | base64 -d > "${ISTIO_CSR_SERVING_CERTFILE}" 

echo "Ensuring an IstioCSR certificate key size is ECC with ${KEY_SIZE}"

TOTAL_CERTS="$(openssl storeutl -noout -text -certs "${ISTIO_CSR_SERVING_CERTFILE}" | grep 'Total found' | awk '{print $3}')"
CERTS_WITH_CORRECT_ALG="$(openssl storeutl -noout -text -certs "${ISTIO_CSR_SERVING_CERTFILE}" | grep "NIST CURVE: P-${KEY_SIZE}" | wc -l)"

echo "$CERTS_WITH_CORRECT_ALG"
echo "$TOTAL_CERTS"
if ! [[ "${CERTS_WITH_CORRECT_ALG}" == "${TOTAL_CERTS}" ]] ; then 
  echo -e "${RED} ✗ Wrong istiod key size got expected ${KEY_SIZE} ${ENDCOLOR}"
  exit 1
fi
echo -e "${GREEN} ✓ Success ${ENDCOLOR}"
set +x