# syntax=docker/dockerfile:1
#
# Multi-stage build for the Viadere backend.
# The build context must be the REPOSITORY ROOT (the server depends on ../Packages/ViadereCore):
#
#   docker build -f Server/Dockerfile -t viadere-server .
#
# ---- build ----------------------------------------------------------------
FROM swift:6.2-jammy AS build
WORKDIR /build

RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl-dev zlib1g-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Resolve dependencies first so they are cached between source changes.
COPY Packages/ViadereCore ./Packages/ViadereCore
COPY Server/Package.swift Server/Package.resolved ./Server/
WORKDIR /build/Server
# SwiftPM requires every declared target's directory to exist, even when only one product is built.
COPY Server/Sources ./Sources
COPY Server/Tests ./Tests
RUN swift package resolve

RUN swift build -c release --product ViadereServer --static-swift-stdlib \
 && mkdir -p /staging \
 && cp "$(swift build -c release --show-bin-path)/ViadereServer" /staging/ViadereServer

# ---- runtime --------------------------------------------------------------
FROM ubuntu:22.04 AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/* \
 # Unprivileged user with no shell and no home directory contents.
 && groupadd --system --gid 10001 viadere \
 && useradd --system --uid 10001 --gid viadere --no-create-home --shell /usr/sbin/nologin viadere

WORKDIR /app
COPY --from=build --chown=viadere:viadere /staging/ViadereServer /app/ViadereServer

ENV ENVIRONMENT=production \
    BIND_HOST=0.0.0.0 \
    PORT=8080

USER viadere:viadere
EXPOSE 8080

ENTRYPOINT ["/app/ViadereServer"]
CMD ["serve", "--env", "production", "--hostname", "0.0.0.0", "--port", "8080"]
