FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
WORKDIR /app
RUN useradd --system --create-home appuser
COPY apps/api/pyproject.toml apps/api/uv.lock ./
RUN pip install --no-cache-dir uv && uv export --locked --no-dev --no-emit-project -o /tmp/requirements.txt && uv pip install --system --no-cache -r /tmp/requirements.txt
COPY apps/api/exposure360_api ./exposure360_api
COPY migrations /migrations
COPY alembic.ini /alembic.ini
USER appuser
EXPOSE 8000
CMD ["uvicorn", "exposure360_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
