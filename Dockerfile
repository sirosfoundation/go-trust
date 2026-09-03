# Build stage
#
# Pinned below 1.27: go-oidfed/lib pulls in lestrrat-go/jwx/v4, which uses
# Go's still-experimental encoding/json/v2 (aliased "jsonv2" in its source).
# That package needs GOEXPERIMENT=jsonv2 to even compile on 1.26.x (below);
# on 1.27.0 the experiment is on by default, but jwx/v4 v4.2.0's own
# internal/json/registry.go references jsonv2.SkipFunc, a symbol that
# Go 1.27.0's actual jsonv2 API no longer has - a real upstream break, not a
# flag issue. Don't bump past 1.26.x without confirming jwx/v4 has a release
# that builds clean against whatever jsonv2 shape the target Go version ships.
FROM golang:1.27.1-alpine AS builder

WORKDIR /app

# Install build dependencies (git for deps, gcc/musl for CGO/PKCS#11)
RUN apk add --no-cache git ca-certificates gcc musl-dev

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with version information
# CGO required for PKCS#11 support via crypto11
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# GOEXPERIMENT=jsonv2: required for jwx/v4's internal/json package on
# Go 1.26.x - see the FROM line's comment above for the full story.
RUN GOEXPERIMENT=jsonv2 CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w -linkmode external -extldflags '-static' -X github.com/sirosfoundation/go-trust/pkg/version.Version=${VERSION} -X github.com/sirosfoundation/go-trust/pkg/version.Commit=${COMMIT} -X github.com/sirosfoundation/go-trust/pkg/version.Date=${BUILD_DATE}" \
    -o gt ./cmd/gt

# Runtime stage - minimal alpine for healthcheck support
FROM alpine:3.24

WORKDIR /app

# Add wget for healthchecks and ca-certificates for TLS
RUN apk add --no-cache ca-certificates wget

# Go 1.23+ rejects x509 certificates with a negative serial number by default
# (RFC 5280 recommends non-negative, but doesn't forbid it, and real-world CA
# tooling - e.g. verifier.multipaz.org's self-generated reader-CA root -
# still produces them; openssl and every other major TLS stack accept them
# without complaint). Without this, AdditionalTrustedRoots/system-CA chain
# validation silently can't parse such a root at all, denying every
# certificate it issues regardless of whitelist membership.
ENV GODEBUG=x509negativeserial=1

# Copy binary from builder
COPY --from=builder /app/gt /app/gt

# Copy example configuration (optional, can be overridden at runtime)
COPY --from=builder /app/example /app/example

# Run as non-root user
RUN adduser -D -u 1000 appuser
USER appuser

EXPOSE 8080

# Health check using wget (assumes server has /healthz endpoint)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/app/gt"]
CMD ["serve"]
