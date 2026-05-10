FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    REPO_PATH=/repo

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --upgrade pip \
    && python -m pip install mcp docker

WORKDIR /repo

COPY scripts/deepseek_driver_mcp.py /opt/deepseek-driver/deepseek_driver_mcp.py

ENTRYPOINT ["python", "/opt/deepseek-driver/deepseek_driver_mcp.py", "--repo", "/repo"]
