FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /var/log/detector

ENV PYTHONUNBUFFERED=1
ENV PATH="/usr/local/bin:$PATH"

CMD ["python", "main.py"]