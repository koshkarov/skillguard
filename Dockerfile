# SkillGuard image: CLI plus a pre-fetched, pinned Cisco skill-scanner, so scans need no PyPI access at run time.
#   docker build -t skillguard .
#   docker run --rm -v "$PWD:/work" -v skillguard-cache:/home/skillguard/.cache/skillguard \
#     -e SKILLGUARD_API_KEY skillguard scan skills/ --sarif skillguard.sarif
# Build with --build-arg EXTRAS=litellm for the LiteLLM backend.
FROM python:3.12-slim

ARG CISCO_PACKAGE=cisco-ai-skill-scanner==2.1.0
ARG EXTRAS=""
ARG UV_VERSION=0.8.17

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_CACHE_DIR=/opt/uv-cache \
    UV_TOOL_DIR=/opt/uv-tools \
    SKILLGUARD_CISCO_PACKAGE=${CISCO_PACKAGE}

RUN pip install "uv==${UV_VERSION}" \
 && useradd --create-home --uid 10001 skillguard \
 && install -d -o skillguard /opt/uv-cache /opt/uv-tools
COPY pyproject.toml README.md /src/
COPY skillguard /src/skillguard
RUN pip install "/src${EXTRAS:+[$EXTRAS]}" && rm -rf /src

# Fetch the pinned scanner as the runtime user, so its cache is writable without a second copy of the layer.
USER skillguard
RUN uvx --quiet --from "${CISCO_PACKAGE}" skill-scanner --help > /dev/null
# Resolve the pinned scanner from the pre-fetched cache only (works air-gapped).
ENV UV_OFFLINE=1
WORKDIR /work
ENTRYPOINT ["skillguard"]
CMD ["--help"]
