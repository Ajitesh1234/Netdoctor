# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim
LABEL org.opencontainers.image.title="NetDoctor" \
      org.opencontainers.image.description="Explain why a website is slow or unreachable" \
      org.opencontainers.image.source="https://github.com/Ajitesh1234/Netdoctor" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping traceroute \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 netdoctor
COPY --from=build /dist/*.whl /tmp/
RUN pip install /tmp/*.whl && rm /tmp/*.whl
# Runs as an unprivileged user. Works with: --read-only --cap-drop ALL --security-opt no-new-privileges
# (ICMP ping needs --cap-add NET_RAW; without it NetDoctor reports the check as "not run" and continues.)
USER 10001
# SIGTERM (docker stop, Kubernetes) triggers a graceful shutdown in watch mode: notifications are flushed.
STOPSIGNAL SIGTERM
ENTRYPOINT ["netdoctor"]
CMD ["--help"]
