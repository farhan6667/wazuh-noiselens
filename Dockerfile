FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/farhan6667/wazuh-noiselens" \
      org.opencontainers.image.description="Measure which Wazuh alerts a proposed suppression would hide, offline." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authors="Syed Farhan Ahmed (SFA), NexaForge"

WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE MANIFEST.in ./
COPY noiselens ./noiselens
RUN python -m pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 app \
    && rm -rf /src

USER app
WORKDIR /work
ENTRYPOINT ["noiselens"]
CMD ["--help"]
