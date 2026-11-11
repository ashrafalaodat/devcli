# syntax=docker/dockerfile:1
FROM golang:1.26.0-bookworm@sha256:2a0ba12e116687098780d3ce700f9ce3cb340783779646aafbabed748fa6677c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then SSL_CERT_FILE=/run/secrets/proxy_ca go mod download; else go mod download; fi
COPY . .
RUN CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/devctld ./cmd/devctld && \
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/devctl ./cmd/devctl && \
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/kubectl-devctl ./cmd/kubectl-devctl
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/ /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/devctld"]
