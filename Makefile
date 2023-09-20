# Copyright 2023 The cert-manager Authors.
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

BINDIR ?= $(CURDIR)/bin
ARCH   ?= $(shell go env GOARCH)
ISTIO_VERSION ?= 1.17.2
K8S_VERSION ?= 1.27.1
IMAGE_PLATFORMS ?= linux/amd64,linux/arm64,linux/arm/v7,linux/ppc64le
VERSION_TAG=v0.7.1

# NOTE FOR DEVELOPERS: "How do the Makefiles work and how can I extend them?"
#
# Shared Makefile logic lives in the make/_shared/ directory. The source of truth for these files
# lies outside of this repository, eg. in the cert-manager/makefile-modules repository.
#
# Logic specific to this repository must be defined in the make/00_mod.mk and make/02_mod.mk files:
#   - The make/00_mod.mk file is included first and contains variable definitions needed by
#     the shared Makefile logic.
#   - The make/02_mod.mk file is included later, it can make use of most of the shared targets
#     defined in the make/_shared/ directory (all targets defined in 00_mod.mk and 01_mod.mk).
#     This file should be used to define targets specific to this repository.

##################################

MAKEFLAGS += --warn-undefined-variables --no-builtin-rules
SHELL := /usr/bin/env bash
.SHELLFLAGS := -uo pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
.SUFFIXES:
FORCE:

noop: # do nothing

##################################
# Host OS and architecture setup #
##################################

# The reason we don't use "go env GOOS" or "go env GOARCH" is that the "go"
# binary may not be available in the PATH yet when the Makefiles are
# evaluated. HOST_OS and HOST_ARCH only support Linux, *BSD and macOS (M1
# and Intel).
HOST_OS ?= $(shell uname -s | tr A-Z a-z)
HOST_ARCH ?= $(shell uname -m)

ifeq (x86_64, $(HOST_ARCH))
	HOST_ARCH = amd64
else ifeq (aarch64, $(HOST_ARCH))
	# linux reports the arm64 arch as aarch64
	HOST_ARCH = arm64
endif

##################################
# Git and versioning information #
##################################

VERSION ?= $(shell git describe --tags --always --match='v*' --abbrev=14 --dirty)
IS_PRERELEASE := $(shell git describe --tags --always --match='v*' --abbrev=0 | grep -q '-' && echo true || echo false)
GITCOMMIT := $(shell git rev-parse HEAD)
GITEPOCH := $(shell git show -s --format=%ct HEAD)

##################################
# Global variables and dirs      #
##################################

bin_dir := _bin

# The ARTIFACTS environment variable is set by the CI system to a directory
# where artifacts should be placed. These artifacts are then uploaded to a
# storage bucket by the CI system (https://docs.prow.k8s.io/docs/components/pod-utilities/).
# An example of such an artifact is a jUnit XML file containing test results.
# If the ARTIFACTS environment variable is not set, we default to a local
# directory in the _bin directory.
ARTIFACTS ?= $(bin_dir)/artifacts

$(bin_dir) $(ARTIFACTS) $(bin_dir)/scratch:
	mkdir -p $@

.PHONY: clean
## Clean all temporary files
## @category [shared] Tools
clean:
	rm -rf $(bin_dir)

##################################
# Include all the Makefiles      #
##################################

-include make/00_mod.mk
-include make/_shared/*/00_mod.mk
-include make/_shared/*/01_mod.mk
-include make/02_mod.mk
-include make/_shared/*/02_mod.mk
