#!/usr/bin/env bash

BINDIR="${BINDIR:-$(pwd)/bin}"
KUBECTL_BIN="${KUBECTL_BIN:-./bin/kind}"

${BINDIR}/kind get kubeconfig --name istio-demo > kubeconfig.yaml
${BINDIR}/ginkgo -nodes 1 test/e2e/ -- --kubeconfig $(pwd)/kubeconfig.yaml
