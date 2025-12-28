# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Copy go mod files
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
ARG SERVICE=api
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /build/bin/api ./cmd/api

# Final stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata procps iproute2

# Create non-root user
RUN addgroup -g 1000 ztnms && \
    adduser -u 1000 -G ztnms -s /bin/sh -D ztnms

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/bin/api /app/service

# Copy config templates
COPY --from=builder /build/configs /app/configs

# Create necessary directories
RUN mkdir -p /etc/zt-nms/tls /etc/zt-nms/keys /etc/zt-nms/ca /var/log/zt-nms && \
    chown -R ztnms:ztnms /app /etc/zt-nms /var/log/zt-nms

USER ztnms

EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/service"]
