#!/bin/bash

KIND_BIN="${KIND_BIN:-./bin/kind}"

$KIND_BIN delete cluster --name istio-demo
docker stop kind-registry
