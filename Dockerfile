FROM golang:1.23-alpine AS builder

WORKDIR /build

RUN apk add --no-cache gcc musl-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -o garde ./cmd/main.go

FROM alpine:3.19 AS service
WORKDIR /app

# sqlite: host snapshot timer / CI run `sqlite3 … VACUUM INTO` via docker exec.
# su-exec: entrypoint chowns bind-mounted /app/data then drops to nonroot.
RUN apk add --no-cache ca-certificates sqlite su-exec \
	&& adduser -D -H -u 65532 nonroot \
	&& mkdir -p /app/certs /app/configs /app/data \
	&& chown -R nonroot:nonroot /app

COPY --from=builder /build/garde .
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /app/garde /docker-entrypoint.sh

# Start as root so the entrypoint can fix bind-mount ownership, then drop to 65532.
ENTRYPOINT ["/bin/sh", "/docker-entrypoint.sh"]
CMD ["./garde"]

EXPOSE 8443
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
	CMD wget -q -O /dev/null http://127.0.0.1:8443/health || exit 1
