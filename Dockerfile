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

FROM go-source AS node-build
ARG HOPX_VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=$HOPX_VERSION" -o /out/hopx-node-linux-amd64 ./cmd/hopx-node
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w -X main.version=$HOPX_VERSION" -o /out/hopx-node-linux-arm64 ./cmd/hopx-node

FROM go-source AS release-verifiers
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /verify/verify-amd64 ./cmd/hopx-release-verify
RUN CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o /verify/verify-arm64 ./cmd/hopx-release-verify

FROM scratch AS node-artifacts
COPY --from=node-build /out/ /
COPY --from=release-verifiers /verify/ /

FROM alpine:3.22
RUN apk add --no-cache ca-certificates openssl
COPY --from=panel /out/hopx-panel /usr/local/bin/hopx-panel
COPY scripts/node-install.sh scripts/node-runner.sh /usr/local/share/hopx/
USER 65532:65532
ENV HOPX_DB=/data/hopx.db HOPX_RELEASES=/releases HOPX_LISTEN=:38471
EXPOSE 38471
ENTRYPOINT ["/usr/local/bin/hopx-panel"]
