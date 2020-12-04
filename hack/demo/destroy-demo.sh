#!/bin/bash

kind delete cluster --name istio-demo
docker stop kind-registry
