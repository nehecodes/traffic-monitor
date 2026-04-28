FROM python:3.11-slim AS build
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync


FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY . .
RUN useradd -m app && chown -R app:app /app
RUN mkdir -p /var/log/detector && chown app:app /var/log/detector
USER app
ENV PATH="$PATH:/app/.venv/bin"
ENV PYTHON_APP=/app
CMD ["python", "main.py"]