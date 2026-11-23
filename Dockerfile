# Produktions-Image: docker build -t ordivus:dev .
# Pin für reproduzierbare Builds per Digest: --build-arg PYTHON_IMAGE=python:3.14-slim@sha256:...
ARG PYTHON_IMAGE=python:3.14-slim

FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/ordivus
COPY pyproject.toml README.md LICENSE /src/
COPY src /src/src
RUN /opt/ordivus/bin/pip install "/src[postgresql,mysql,redis]" \
 && /opt/ordivus/bin/pip uninstall -y pip

FROM ${PYTHON_IMAGE}
ARG VERSION=0.1.0
ARG REVISION=unknown
LABEL org.opencontainers.image.title="ordivus" \
      org.opencontainers.image.description="Stateless, declarative reconciliation engine for administrative configuration." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
# Kein Bytecode-Schreiben: Image läuft mit readOnlyRootFilesystem.
ENV PATH=/opt/ordivus/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /opt/ordivus /opt/ordivus
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["ordivus"]
CMD ["--help"]
