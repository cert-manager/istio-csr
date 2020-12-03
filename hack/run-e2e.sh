#!/bin/bash

BINDIR="${BINDIR:-$(pwd)/bin}"

function cleanup()
{
  kind delete cluster --name istio-demo
  docker stop kind-registry
}

trap cleanup EXIT

kind get kubeconfig --name istio-demo > kubeconfig.yaml
${BINDIR}/ginkgo -nodes 1 test/e2e/ -- --kubeconfig $(pwd)/kubeconfig.yaml
