# ============ STAGE 1: BUILD ============
FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o main cmd/api/main.go

# ============ STAGE 2: RUNTIME ============
FROM alpine:latest

RUN apk --no-cache add ca-certificates curl
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app
COPY --from=builder /app/main .
COPY --from=builder /app/l10n ./l10n/

USER appuser
EXPOSE 8080
CMD ["./main"]
