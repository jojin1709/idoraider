# Build Stage
FROM golang:1.22-alpine AS builder

WORKDIR /src

# Copy module definition
COPY go.mod ./

# Copy all source files
COPY . .

# Build statically linked binary with stripped debug symbols
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /idoraider ./cmd/idoraider

# Final Minimal Stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

WORKDIR /work

# Copy compiled binary and scan templates
COPY --from=builder /idoraider /usr/local/bin/idoraider
COPY --from=builder /src/templates /templates

# Default entrypoint
ENTRYPOINT ["idoraider"]
CMD ["-h"]
