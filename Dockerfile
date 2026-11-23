# Produktions-Image: docker build -t ordivus:dev .
# Basis-Image per Digest gepinnt (python:3.14-slim); Aktualisieren:
#   docker buildx imagetools inspect python:3.14-slim  -> Digest hier eintragen
ARG PYTHON_IMAGE=python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f

FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/ordivus
# Abhängigkeiten nur aus dem hash-gepinnten Lock (requirements.lock, siehe docs/entwicklung.md).
COPY requirements.lock /src/
RUN /opt/ordivus/bin/pip install --require-hashes --only-binary=:all: -r /src/requirements.lock
COPY pyproject.toml README.md LICENSE /src/
COPY src /src/src
# Build-Backend (setuptools) kommt ebenfalls aus dem Lock, daher ohne Build-Isolation.
RUN /opt/ordivus/bin/pip install --no-deps --no-build-isolation /src \
 && /opt/ordivus/bin/pip uninstall -y setuptools pip

FROM ${PYTHON_IMAGE}
ARG VERSION=0.1.0
ARG REVISION=unknown
LABEL org.opencontainers.image.title="ordivus" \
      org.opencontainers.image.description="Stateless, declarative reconciliation engine for administrative configuration." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
# Sicherheitsupdates des Basis-Image einspielen; pip/setuptools/wheel werden zur Laufzeit nicht gebraucht.
RUN apt-get update && apt-get -y upgrade && rm -rf /var/lib/apt/lists/* \
 && rm -rf /usr/local/lib/python3.*/site-packages/pip* /usr/local/lib/python3.*/site-packages/setuptools* \
           /usr/local/lib/python3.*/site-packages/wheel* /usr/local/bin/pip*
# Kein Bytecode-Schreiben: Image läuft mit readOnlyRootFilesystem.
ENV PATH=/opt/ordivus/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /opt/ordivus /opt/ordivus
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["ordivus"]
CMD ["--help"]
