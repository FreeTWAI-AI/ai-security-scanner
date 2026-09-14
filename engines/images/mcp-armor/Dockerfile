# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH=1774602347

FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS source

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 GOTOOLCHAIN=local SOURCE_DATE_EPOCH=1774602347

RUN apk add --no-cache git=2.52.0-r0

ADD --checksum=sha256:6bf3da5f1332748eb0dc60fb1f82f1ee43bb721f70686f99f4f262d256da45a6 \
    https://github.com/aira-security/mcp-armor/archive/6af4cee4665ab6242f02a88952f9127b6a04922a.tar.gz \
    /tmp/mcp-armor-source.tar.gz
RUN mkdir -p /src/mcp-armor \
    && tar -xzf /tmp/mcp-armor-source.tar.gz --strip-components=1 -C /src/mcp-armor

COPY docs/research/patches/mcp-armor-1.0.2-config-only.patch /tmp/mcp-armor-config-only.patch
WORKDIR /src/mcp-armor
RUN echo 'ae7732b5f9c922fbf2bee54e0246cccde6e1e5af829db112eb0f948cbd424122  /tmp/mcp-armor-config-only.patch' | sha256sum -c - \
    && git apply --check /tmp/mcp-armor-config-only.patch \
    && git apply /tmp/mcp-armor-config-only.patch \
    && grep -F '__version__ = "1.0.2"' src/mcp_armor/__init__.py

WORKDIR /src/launcher
COPY engines/images/mcp-armor/launcher/go.mod engines/images/mcp-armor/launcher/main.go engines/images/mcp-armor/launcher/main_test.go ./
RUN test -z "$(gofmt -d main.go main_test.go)" \
    && go test ./... \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
       -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
       -o /out/ai-security-scanner-mcp-armor-entrypoint .

FROM python:3.11.16-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7 AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    SOURCE_DATE_EPOCH=1774602347

COPY engines/images/mcp-armor/requirements.lock /tmp/requirements.lock
COPY --from=source /src/mcp-armor /src/mcp-armor
RUN echo '86d9dfb49bdd485ebb7855fda467c2cd6ac93c2a91609c08fa9e476c6dc746f8  /tmp/requirements.lock' | sha256sum -c - \
    && python -m pip install \
       --no-compile \
       --only-binary=:all: \
       --require-hashes \
       --prefix=/install \
       --requirement=/tmp/requirements.lock \
    && mkdir -p /install/lib/python3.11/site-packages \
    && cp -a /src/mcp-armor/src/mcp_armor /install/lib/python3.11/site-packages/ \
    && PYTHONPATH=/install/lib/python3.11/site-packages \
       python -m mcp_armor.cli scan --config-only \
       --config /src/mcp-armor/tests/fixtures/config-clean.json \
       --report-type json --output /tmp/config-clean-output.json \
    && PYTHONPATH=/install/lib/python3.11/site-packages \
       python -c 'import json; value=json.load(open("/tmp/config-clean-output.json", encoding="utf-8")); assert value["scanner_version"] == "1.0.2" and value["input_count"] == 1 and value["evaluated_input_count"] == 1 and value["complete"] is True and len(value["checks"]) == 2' \
    && ! find /install -type d \( -name 'fastmcp' -o -name 'transformers' -o -name 'torch' -o -name 'thefuzz' \) | grep . \
    && find /install -exec touch -h -d '@1774602347' '{}' +

FROM python:3.11.16-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7

LABEL org.opencontainers.image.title="ai-security-scanner MCP Armor engine" \
      org.opencontainers.image.description="Pinned-source offline MCP configuration checks without server contact or model dependencies" \
      org.opencontainers.image.source="https://github.com/aira-security/mcp-armor" \
      org.opencontainers.image.revision="6af4cee4665ab6242f02a88952f9127b6a04922a" \
      org.opencontainers.image.version="1.0.2-config-only.1" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.ai-security-scanner.source-archive-sha256="6bf3da5f1332748eb0dc60fb1f82f1ee43bb721f70686f99f4f262d256da45a6" \
      io.ai-security-scanner.patch-sha256="ae7732b5f9c922fbf2bee54e0246cccde6e1e5af829db112eb0f948cbd424122" \
      io.ai-security-scanner.requirements-sha256="86d9dfb49bdd485ebb7855fda467c2cd6ac93c2a91609c08fa9e476c6dc746f8"

ENV HOME="/tmp/ai-security-scanner-home" \
    NO_COLOR="1" \
    PIP_DISABLE_PIP_VERSION_CHECK="1" \
    PYTHONDONTWRITEBYTECODE="1" \
    PYTHONHASHSEED="0" \
    PYTHONNOUSERSITE="1" \
    PYTHONUNBUFFERED="1" \
    XDG_CACHE_HOME="/tmp/ai-security-scanner-cache"

COPY --from=build /install /usr/local
COPY --from=source /out/ai-security-scanner-mcp-armor-entrypoint /usr/local/bin/ai-security-scanner-mcp-armor-entrypoint
COPY --from=source /src/mcp-armor/LICENSE /usr/share/licenses/mcp-armor/LICENSE
COPY --from=source /tmp/mcp-armor-config-only.patch /usr/share/source/mcp-armor-1.0.2-config-only.patch
COPY engines/images/mcp-armor/requirements.lock /usr/share/source/mcp-armor-requirements.lock
COPY engines/images/mcp-armor/Dockerfile /usr/share/source/ai-security-scanner-mcp-armor.Dockerfile
COPY LICENSE /usr/share/licenses/ai-security-scanner/LICENSE

RUN mkdir -p /workspace /output /tmp/ai-security-scanner-home /tmp/ai-security-scanner-cache \
    && chmod 1777 /tmp /tmp/ai-security-scanner-home /tmp/ai-security-scanner-cache \
    && touch -h -d '@1774602347' \
       /workspace /output /tmp/ai-security-scanner-home /tmp/ai-security-scanner-cache \
       /usr/share/licenses/mcp-armor/LICENSE \
       /usr/share/licenses/ai-security-scanner/LICENSE \
       /usr/share/source/mcp-armor-1.0.2-config-only.patch \
       /usr/share/source/mcp-armor-requirements.lock \
       /usr/share/source/ai-security-scanner-mcp-armor.Dockerfile

WORKDIR /workspace
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/ai-security-scanner-mcp-armor-entrypoint"]
