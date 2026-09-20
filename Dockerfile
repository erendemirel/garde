FROM golang:1.27-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# No CGO: durable state is PostgreSQL (lib/pq), ephemeral state is Redis.
RUN CGO_ENABLED=0 GOOS=linux go build -o garde ./cmd/main.go

FROM alpine:3.19 AS service
WORKDIR /app

RUN apk add --no-cache ca-certificates wget \
	&& adduser -D -H -u 65532 nonroot \
	&& mkdir -p /app/certs /app/configs \
	&& chown -R nonroot:nonroot /app

COPY --from=builder /build/garde .
USER nonroot:nonroot

CMD ["./garde"]

EXPOSE 8443
# Probe HTTPS first (USE_TLS=true), then HTTP (reverse-proxy / USE_TLS=false).
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
	CMD wget -q -O /dev/null --no-check-certificate https://127.0.0.1:8443/ready || wget -q -O /dev/null http://127.0.0.1:8443/ready || exit 1
