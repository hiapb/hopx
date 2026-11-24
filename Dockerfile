FROM node:24-alpine AS ui
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.26.11-alpine AS go-source
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/

FROM go-source AS panel
COPY web/*.go web/index.html web/
COPY --from=ui /src/web/dist web/dist
ARG HOPX_VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -tags webdist -ldflags="-s -w -X main.version=$HOPX_VERSION" -o /out/hopx-panel ./cmd/hopx-panel

FROM --platform=$BUILDPLATFORM alpine:3.22 AS haproxy-source
RUN apk add --no-cache curl
ARG HAPROXY_VERSION=3.2.27
ARG HAPROXY_SHA256=3363a337dcde55a871b0f63ac483a4476db647418b85dee069b35f39291ee177
WORKDIR /build
RUN curl --proto '=https' -fsS "https://www.haproxy.org/download/3.2/src/haproxy-${HAPROXY_VERSION}.tar.gz" -o source.tar.gz \
    && echo "${HAPROXY_SHA256}  source.tar.gz" | sha256sum -c

# Keep the build tools native. The target HAProxy binaries are only copied
# into the node releases, so the build host never has to execute them.
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS haproxy-build
ARG BUILDARCH
RUN case "$BUILDARCH" in \
      amd64) cross=aarch64-linux-gnu; cross_libc=libc6-dev-arm64-cross ;; \
      arm64) cross=x86-64-linux-gnu; cross_libc=libc6-dev-amd64-cross ;; \
      *) echo "Unsupported HAProxy build architecture: $BUILDARCH" >&2; exit 1 ;; \
    esac \
    && apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev binutils make "gcc-$cross" "$cross_libc" \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY --from=haproxy-source /build/source.tar.gz ./
RUN set -eu; mkdir /out; \
    for arch in amd64 arm64; do \
      case "$arch" in \
        amd64) triple=x86_64-linux-gnu; machine='X86-64' ;; \
        arm64) triple=aarch64-linux-gnu; machine='AArch64' ;; \
      esac; \
      if [ "$arch" = "$BUILDARCH" ]; then prefix=''; else prefix="$triple-"; fi; \
      mkdir "$arch"; tar -xzf source.tar.gz -C "$arch" --strip-components=1; \
      make -C "$arch" -j4 TARGET=linux-glibc CC="${prefix}gcc" LDFLAGS=-static \
        USE_LIBCRYPT= USE_CRYPT_H= USE_LUA= USE_OPENSSL= USE_PCRE= USE_PCRE2= USE_ZLIB=; \
      "${prefix}strip" "$arch/haproxy"; \
      LC_ALL=C readelf -h "$arch/haproxy" | grep -q "Machine:.*$machine"; \
      LC_ALL=C readelf -l "$arch/haproxy" > "$arch/program-headers"; \
      if grep -q 'INTERP' "$arch/program-headers"; then echo "HAProxy must be statically linked" >&2; exit 1; fi; \
      gzip -n -9 -c "$arch/haproxy" > "/out/haproxy-$arch.gz"; \
    done

FROM go-source AS node-build
ARG HOPX_VERSION=dev
COPY --from=haproxy-build /out/ /tmp/
RUN cp /tmp/haproxy-amd64.gz internal/node/haproxy.gz \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags bundledhaproxy -trimpath -ldflags="-s -w -X main.version=$HOPX_VERSION" -o /out/hopx-node-linux-amd64 ./cmd/hopx-node
RUN cp /tmp/haproxy-arm64.gz internal/node/haproxy.gz \
    && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags bundledhaproxy -trimpath -ldflags="-s -w -X main.version=$HOPX_VERSION" -o /out/hopx-node-linux-arm64 ./cmd/hopx-node

FROM go-source AS release-verifiers
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /verify/verify-amd64 ./cmd/hopx-release-verify
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o /verify/verify-arm64 ./cmd/hopx-release-verify

FROM scratch AS node-artifacts
COPY --from=node-build /out/ /
COPY --from=release-verifiers /verify/ /
COPY --from=haproxy-source /build/source.tar.gz /haproxy-source.tar.gz

FROM alpine:3.22 AS geoip
COPY assets/geoip/country.mmdb.gz /tmp/country.mmdb.gz
RUN gzip -dc /tmp/country.mmdb.gz > /tmp/country.mmdb

FROM alpine:3.22
RUN apk add --no-cache ca-certificates openssl
COPY --from=panel /out/hopx-panel /usr/local/bin/hopx-panel
COPY --from=geoip /tmp/country.mmdb /usr/local/share/hopx/country.mmdb
COPY assets/geoip/README.md /usr/local/share/hopx/geoip-attribution.md
COPY scripts/node-install.sh scripts/node-runner.sh /usr/local/share/hopx/
USER 65532:65532
ENV HOPX_GEOIP_DB=/usr/local/share/hopx/country.mmdb HOPX_DB=/data/hopx.db HOPX_RELEASES=/releases HOPX_LISTEN=:38471
EXPOSE 38471
ENTRYPOINT ["/usr/local/bin/hopx-panel"]
