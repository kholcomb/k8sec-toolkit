# Multi-stage build for k8sec-toolkit
FROM golang:1.24-alpine AS builder

# Install security tools and git
RUN apk add --no-cache git ca-certificates tzdata

# Create non-root user for security
RUN adduser -D -s /bin/sh k8sec

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the binary with security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o k8sec-toolkit \
    ./cmd/k8sec-toolkit/main.go

# Final stage - minimal runtime image
FROM scratch

# Import ca-certs, timezone data, and user from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd

# Copy the binary
COPY --from=builder /build/k8sec-toolkit /k8sec-toolkit

# Use non-root user
USER k8sec

# Add labels for metadata
LABEL maintainer="k8sec-toolkit" \
      org.opencontainers.image.title="K8Sec Toolkit" \
      org.opencontainers.image.description="Kubernetes Security Scanner" \
      org.opencontainers.image.source="https://github.com/kholcomb/k8sec-toolkit" \
      org.opencontainers.image.documentation="https://github.com/kholcomb/k8sec-toolkit/blob/main/README.md" \
      org.opencontainers.image.licenses="Apache-2.0"

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/k8sec-toolkit", "version"]

# Default command
ENTRYPOINT ["/k8sec-toolkit"]
