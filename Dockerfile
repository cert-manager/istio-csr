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

FROM gcr.io/distroless/static@sha256:3cd546c0b3ddcc8cae673ed078b59067e22dea676c66bd5ca8d302aef2c6e845
LABEL description="istio certificate agent to serve certificate signing requests via cert-manager"

COPY ./bin/cert-manager-istio-csr-linux /usr/bin/cert-manager-istio-csr

ENTRYPOINT ["/usr/bin/cert-manager-istio-csr"]
