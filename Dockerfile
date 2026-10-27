# syntax=docker/dockerfile:1

# -- Stage 1: Downloader
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS downloader
RUN apk add --no-cache ca-certificates tzdata

# -- Stage 2: Builder
FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
# Release version reported in the LAPI User-Agent; image.yml passes it for main builds
ARG VERSION=dev
# Build static binary, ensuring CGO is disabled
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-w -s -X github.com/hononeko/cs-edl-bouncer/pkg/version.Version=${VERSION}" -o /out/bouncer ./cmd/bouncer

# -- Stage 3: Final Image (minimal static distroless)
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
WORKDIR /
# Copy certs & tzdata from downloader
COPY --from=downloader /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=downloader /usr/share/zoneinfo /usr/share/zoneinfo

# Copy compiled binary from builder
COPY --from=builder /out/bouncer /app/bouncer

# Adhere to rootless mandates
USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/app/bouncer"]
