# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install git (needed by go mod for some deps)
RUN apk add --no-cache git

COPY go.mod ./
COPY . .
# go mod tidy generates go.sum and resolves all deps
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o bluerange ./cmd/server

# ── Final image ───────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy binary
COPY --from=builder /build/bluerange /app/bluerange

# Copy web assets and lab content (can be overridden by volume mount)
COPY web/ /app/web/
COPY labs/ /app/labs/

# Data directory (override via volume)
RUN mkdir -p /app/data

EXPOSE 8080

ENV ADDR=:8080 \
    DATA_DIR=/app/data \
    LABS_DIR=/app/labs \
    STATIC_DIR=/app/web/static \
    TMPL_DIR=/app/web/templates \
    ADMIN_USER=admin \
    ADMIN_PASS=changeme

ENTRYPOINT ["/app/bluerange"]
