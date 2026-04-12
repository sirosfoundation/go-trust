# Build stage
FROM golang:1.26-alpine AS builder

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

RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w -linkmode external -extldflags '-static' -X github.com/sirosfoundation/go-trust/pkg/version.Version=${VERSION} -X github.com/sirosfoundation/go-trust/pkg/version.Commit=${COMMIT} -X github.com/sirosfoundation/go-trust/pkg/version.Date=${BUILD_DATE}" \
    -o gt ./cmd/gt

# Runtime stage - minimal alpine for healthcheck support
FROM alpine:3.23

WORKDIR /app

# Add wget for healthchecks and ca-certificates for TLS
RUN apk add --no-cache ca-certificates wget

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
