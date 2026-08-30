# Qualification gate: replace this exact version tag with a verified immutable digest before release.
FROM python:3.12.11-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN useradd --create-home --uid 10001 chronos
WORKDIR /app
COPY pyproject.toml /app/
COPY src /app/src
COPY run_stage2.py verify_stage2.py /app/
COPY config /app/config
COPY schemas /app/schemas
RUN pip install --no-cache-dir pandas==2.3.1 jsonschema==4.25.0 pyyaml==6.0.2 pytest==8.4.1
USER chronos
ENTRYPOINT ["python", "run_stage2.py"]
