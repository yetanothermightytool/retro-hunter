FROM python:3.12-slim AS builder

WORKDIR /app

# Install dependencies in venv
COPY requirements.txt ./
RUN python -m venv /opt/venv && \
   /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

COPY --from=builder --chown=appuser:appuser /opt/venv /opt/venv
COPY --chown=appuser:appuser app ./app

ENV PATH="/opt/venv/bin:$PATH"

USER appuser

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
