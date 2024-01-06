#!/usr/bin/env bash

BINDIR="${BINDIR:-$(pwd)/bin}"
ARTIFACTS="${ARTIFACTS:-$(pwd)/_artifacts}"
KUBECTL_BIN="${KUBECTL_BIN:-./bin/kind}"

${BINDIR}/kind get kubeconfig --name istio-demo > kubeconfig.yaml
${BINDIR}/ginkgo --junit-report=${ARTIFACTS}/junit-go-e2e.xml -nodes 1 test/e2e/ -- --kubeconfig $(pwd)/kubeconfig.yaml
