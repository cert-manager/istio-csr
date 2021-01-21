FROM gcr.io/distroless/static@sha256:3cd546c0b3ddcc8cae673ed078b59067e22dea676c66bd5ca8d302aef2c6e845
LABEL description="istio certificate agent to serve certificate signing requests via cert-manager"

COPY ./bin/cert-manager-istio-csr-linux /usr/bin/cert-manager-istio-csr

ENTRYPOINT ["/usr/bin/cert-manager-istio-csr"]
