FROM alpine:3.12
LABEL description="istio certificate agent to serve certificate signing requests via cert-manager"

RUN apk --no-cache add ca-certificates

COPY ./bin/cert-manager-istio-agent-linux /usr/bin/cert-manager-istio-agent

ENTRYPOINT ["/usr/bin/cert-manager-istio-agent"]
