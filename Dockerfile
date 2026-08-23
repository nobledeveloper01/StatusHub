# Multi-stage, distroless, non-root, read-only rootfs (§11.8).
#
# The final image contains the binary, the CA bundle and nothing else. There
# is no shell, no package manager and no libc — so a remote-code-execution bug
# in StatusHub lands an attacker in an image with nothing to execute, and a
# container scanner has almost no surface to report on.

FROM golang:1.25-alpine AS build

# git is needed for the version stamp; ca-certificates is copied into the
# final image rather than installed there.
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Dependencies first, so a code change does not re-download the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown

# CGO off so the binary is static and can run in a distroless image.
# -trimpath keeps build machine paths out of the binary, which is both a small
# information leak and the main obstacle to a reproducible build.
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X github.com/nobledeveloper01/StatusHub/internal/server.Version=${VERSION} -X github.com/nobledeveloper01/StatusHub/internal/server.Commit=${COMMIT}" \
      -o /out/statushub ./cmd/statushub \
 && CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X github.com/nobledeveloper01/StatusHub/internal/server.Version=${VERSION} -X github.com/nobledeveloper01/StatusHub/internal/server.Commit=${COMMIT}" \
      -o /out/statushubctl ./cmd/statushubctl

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# tzdata is not optional. Several adapters read provider timestamps that carry
# no zone and must be interpreted as Africa/Lagos; without the database that
# lookup fails and every one of those events is flagged incomplete.
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo

COPY --from=build /out/statushub /usr/local/bin/statushub
COPY --from=build /out/statushubctl /usr/local/bin/statushubctl

USER nonroot:nonroot
EXPOSE 8080 8081

ENV STATUSHUB_LISTEN_ADDR=:8080 \
    STATUSHUB_API_LISTEN_ADDR=:8081 \
    STATUSHUB_LOG_FORMAT=json

ENTRYPOINT ["/usr/local/bin/statushub"]
CMD ["serve"]
