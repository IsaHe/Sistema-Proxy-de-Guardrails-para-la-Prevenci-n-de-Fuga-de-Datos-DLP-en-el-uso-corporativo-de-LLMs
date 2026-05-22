FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system --gid 1001 appuser \
    && useradd --system --uid 1001 --gid appuser --home /app --shell /sbin/nologin appuser \
    && mkdir -p /app \
    && chown appuser:appuser /app

WORKDIR /app

COPY --chown=appuser:appuser requirements.txt ./

# --- CAPA NLP ---
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appuser app ./app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]