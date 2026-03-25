FROM golang:1.22-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang-15 libbpf-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN go generate ./... \
    && go build -trimpath -ldflags "-s -w -X main.Version=$(git describe --tags)" -o /out/rsbpd ./cmd/rsbpd

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /nonexistent --shell /usr/sbin/nologin rsbp

WORKDIR /
COPY --from=builder /out/rsbpd /rsbpd
COPY config/rsbp.yaml /etc/rsbp/rsbp.yaml

RUN mkdir -p /var/log/rsbp /var/lib/rsbp /etc/rsbp \
    && chown -R rsbp:rsbp /var/log/rsbp /var/lib/rsbp /etc/rsbp

EXPOSE 9001 9090
USER rsbp

ENTRYPOINT ["/rsbpd", "run"]
