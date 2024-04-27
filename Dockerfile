FROM --platform=linux/amd64 golang:1.22-bookworm AS base

WORKDIR /src

COPY ./  .

RUN apt-get update && \
    apt-get install -y git coreutils && \
    apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV GOPROXY=https://proxy.golang.org
RUN --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go mod download

FROM base AS builder

ENV CGO_ENABLED=0
ARG VERSION_VAR

RUN mkdir /app
COPY ./  /app/
WORKDIR /app
RUN --mount=target=. \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X \"main.version=${VERSION_VAR}\"" -o /out/ipscout \
    && chmod +x /out/ipscout

FROM --platform=linux/amd64 gcr.io/distroless/static-debian12:nonroot-amd64
LABEL maintainer="Jon Hadfield jon@lessknown.co.uk"

WORKDIR /app
COPY --from=builder /out/ipscout /app/ipscout
ENTRYPOINT ["/app/ipscout"]
