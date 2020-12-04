#!/bin/bash

BINDIR="${BINDIR:-$(pwd)/bin}"

kind get kubeconfig --name istio-demo > kubeconfig.yaml
${BINDIR}/ginkgo -nodes 1 test/e2e/ -- --kubeconfig $(pwd)/kubeconfig.yaml
