# syntax=docker/dockerfile:1
# Stage 1: Build
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src
RUN mkdir -p /data-init
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG TARGETVARIANT
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN GOARM=${TARGETVARIANT#v} CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}" \
    -o /out/cs-unifi-bouncer-pro \
    ./cmd/bouncer
RUN mkdir -p /out/data-init

# Stage 2: Distroless runtime
FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="cs-unifi-bouncer-pro" \
      org.opencontainers.image.description="Production-grade CrowdSec bouncer for UniFi network controllers" \
      org.opencontainers.image.url="https://github.com/developingchet/cs-unifi-bouncer-pro" \
      org.opencontainers.image.source="https://github.com/developingchet/cs-unifi-bouncer-pro" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder /out/cs-unifi-bouncer-pro /cs-unifi-bouncer-pro
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder --chown=65532:65532 /out/data-init /data

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD ["/cs-unifi-bouncer-pro", "healthcheck"]

# Expose Prometheus metrics and health endpoints
EXPOSE 9090 8081

ENTRYPOINT ["/cs-unifi-bouncer-pro"]
CMD ["run"]
