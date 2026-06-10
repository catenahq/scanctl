# Slim-ish image for running scanctl. It carries the Go toolchain because the Go
# scanners (govulncheck via go install, gosec loading packages) need it at scan
# time; the release scanners (trivy/osv/gitleaks) are still lazy-fetched. git is
# present so gitleaks can walk full history. Network is required at scan time.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION#v}" \
    -o /out/scanctl ./cmd/scanctl

FROM golang:1.26-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 10001 scanctl
COPY --from=build /out/scanctl /usr/local/bin/scanctl
# Run unprivileged. HOME must be writable: go install (govulncheck) writes to
# $HOME/go + $HOME/.cache, and the scanner cache defaults under $HOME/.cache.
USER scanctl
ENV HOME=/home/scanctl
WORKDIR /repo
HEALTHCHECK CMD ["scanctl", "version"]
ENTRYPOINT ["scanctl"]
CMD ["run", "."]
