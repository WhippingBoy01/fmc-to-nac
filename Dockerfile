FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Copy metadata and source, then install the package (and runtime dependencies).
COPY pyproject.toml README.md LICENSE requirements.txt ./
COPY fmc_to_nac ./fmc_to_nac
RUN pip install --no-cache-dir .

# Run as non-root. /out is the default output/work directory mount.
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /out \
    && chown -R appuser:appuser /out
USER appuser

VOLUME ["/out"]
WORKDIR /out

ENTRYPOINT ["fmc-to-nac"]
CMD ["--help"]
