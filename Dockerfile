FROM golang:1.22-alpine3.18 AS builder
RUN apk add --no-cache git

WORKDIR /usr/src
COPY go.mod /usr/src/go.mod
COPY go.sum /usr/src/go.sum
RUN go mod download

COPY cmd cmd
COPY internal internal
COPY internal internal

RUN go build -o jwt-builder -ldflags="-s -w" cmd/jwt-builder/main.go 

FROM alpine:3.18
WORKDIR /usr/bin
COPY --from=builder /usr/src/jwt-builder .
ENTRYPOINT ["/usr/bin/jwt-builder"]