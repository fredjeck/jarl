# use a builder image for building cloudflare
ARG TARGET_GOOS=linux
ARG TARGET_GOARCH=amd64
FROM golang:1.22.2 as builder
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    TARGET_GOOS=${TARGET_GOOS} \
    TARGET_GOARCH=${TARGET_GOARCH}

WORKDIR /go/src/github.com/fredjeck/jarl/

# install dependancies
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# copy our sources into the builder image
COPY . .

# build
RUN go build -o /go/src/github.com/fredjeck/jarl/bin/jarl ./cmd/jarl


# use a distroless base image with glibc
FROM alpine:3.19

LABEL org.opencontainers.image.source="https://github.com/fredjeck/jarl"

RUN apk update && \
    apk add --no-cache shadow && \
    groupadd muggles && \
    useradd -ms /bin/sh -G muggles jarl

# copy our compiled binary
COPY --from=builder --chown=jarl /go/src/github.com/fredjeck/jarl/bin/jarl /usr/local/bin/

RUN mkdir -p /var/run/jarl/configuration
RUN chown jarl /var/run/jarl/configuration

# run as non-privileged user
USER jarl

ENV PORT_GRPC=9000
ENV PORT_HTTP=8000
ENV AUTHZ_HEADER=x-forwarded-sub

# command / entrypoint of container
ENTRYPOINT jarl -h  ${PORT_HTTP} -g ${PORT_GRPC} -a ${AUTHZ_HEADER}

EXPOSE ${PORT_HTTP}
EXPOSE ${PORT_GRPC}