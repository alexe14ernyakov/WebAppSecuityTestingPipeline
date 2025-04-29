FROM golang:1.21-alpine

RUN apk add --no-cache git && \
    go install github.com/OJ/gobuster/v3@latest

ENTRYPOINT ["gobuster"]
