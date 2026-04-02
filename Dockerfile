# Build
FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY . .

RUN go build -o /scanner ./cmd/cli/

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

COPY --from=builder /scanner /scanner

ENTRYPOINT ["/scanner"]
