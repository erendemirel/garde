FROM golang:1.22-alpine AS builder

WORKDIR /build

RUN apk add --no-cache gcc musl-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -o auth_service ./cmd/main.go

FROM alpine:3.19 AS service
WORKDIR /app
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/auth_service .
RUN mkdir -p /app/certs /app/configs
RUN chmod +x /app/auth_service
CMD ["./auth_service"] 