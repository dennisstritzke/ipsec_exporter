# Builder container.
FROM golang:1.12.7-alpine3.10 AS builder

COPY . /go/src/github.com/dennisstritzke/ipsec_exporter
WORKDIR /go/src/github.com/dennisstritzke/ipsec_exporter

RUN adduser -D -u 10001 scratchuser

RUN apk --no-cache add git
RUN go get github.com/Masterminds/glide
RUN glide install

ENV CGO_ENABLED=0
RUN go build \
    --ldflags '-extldflags "-static"' \
    -o build/ipsec_exporter \
    github.com/dennisstritzke/ipsec_exporter

# Artifact container.
FROM scratch

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /go/src/github.com/dennisstritzke/ipsec_exporter/build/ipsec_exporter /ipsec_exporter

USER scratchuser
