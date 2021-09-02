#!/bin/bash

KIND_BIN="${KIND_BIN:-./bin/kind}"

$KIND_BIN export logs _artifacts --name istio-demo
$KIND_BIN delete cluster --name istio-demo
