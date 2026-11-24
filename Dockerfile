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

FROM --platform=linux/amd64 alpine:3.22 AS haproxy-amd64
RUN apk add --no-cache build-base linux-headers
WORKDIR /build
COPY --from=haproxy-source /build/source.tar.gz ./
RUN tar -xzf source.tar.gz --strip-components=1 \
    && make -j4 TARGET=linux-musl LDFLAGS=-static USE_LUA= USE_OPENSSL= USE_PCRE= USE_PCRE2= USE_ZLIB= \
    && strip haproxy && gzip -n -9 -c haproxy > /haproxy.gz

FROM --platform=linux/arm64 alpine:3.22 AS haproxy-arm64
RUN apk add --no-cache build-base linux-headers
WORKDIR /build
COPY --from=haproxy-source /build/source.tar.gz ./
RUN tar -xzf source.tar.gz --strip-components=1 \
    && make -j4 TARGET=linux-musl LDFLAGS=-static USE_LUA= USE_OPENSSL= USE_PCRE= USE_PCRE2= USE_ZLIB= \
    && strip haproxy && gzip -n -9 -c haproxy > /haproxy.gz

FROM go-source AS node-build
ARG HOPX_VERSION=dev
COPY --from=haproxy-amd64 /haproxy.gz /tmp/haproxy-amd64.gz
COPY --from=haproxy-arm64 /haproxy.gz /tmp/haproxy-arm64.gz
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
