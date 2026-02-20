# syntax=docker/dockerfile:1
# Stage 1: Build
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG TARGETVARIANT
ARG VERSION=dev
RUN GOARM=${TARGETVARIANT#v} CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o /out/cs-unifi-bouncer-pro \
    ./cmd/bouncer

# Stage 2: Distroless runtime
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/cs-unifi-bouncer-pro /cs-unifi-bouncer-pro
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Expose Prometheus metrics and health endpoints
EXPOSE 9090 8081

ENTRYPOINT ["/cs-unifi-bouncer-pro", "run"]
