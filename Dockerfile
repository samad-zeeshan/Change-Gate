FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.lock ./
RUN pip install --upgrade pip && pip install -r requirements.lock

COPY pyproject.toml ./
COPY src ./src
COPY eval ./eval
COPY db ./db
RUN pip install -e . --no-deps

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY scripts ./scripts

EXPOSE 9000
CMD ["python", "-m", "change_gate.server.app"]
