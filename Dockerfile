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
# create a default directory for the configuration in order to copy it to the runtime image as mkdir is not available on distroless
RUN mkdir -p /var/run/jarl/configuration

# use a distroless base image with glibc
FROM gcr.io/distroless/base-debian12:nonroot

LABEL org.opencontainers.image.source="hhttps://github.com/fredjeck/jarl"

# copy our compiled binary
COPY --from=builder --chown=nonroot /go/src/github.com/fredjeck/jarl/bin/jarl /usr/local/bin/
COPY --from=builder --chown=nonroot /var/run/jarl/configuration /var/run/jarl/configuration

# run as non-privileged user
USER nonroot

ARG PORT_GRPC=9000
ARG PORT_HTTP=8000
ARG AUTHZ_HEADER=x-forwarded-sub
ARG CONFIGURATION=/var/run/jarl/configuration
ENV CONFIGURATION=${CONFIGURATION}

# command / entrypoint of container
ENTRYPOINT ["jarl"]
#,"-h","$PORT_HTTP","-g","$PORT_HTTP","-a","$AUTHZ_HEADER","-c",$CONFIGURATION]

EXPOSE  $PORT_GRPC
EXPOSE  $PORT_HTTP