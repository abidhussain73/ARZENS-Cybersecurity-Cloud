FROM python:3.12-slim
WORKDIR /app
RUN useradd --system --create-home appuser
COPY apps/api/pyproject.toml apps/api/uv.lock ./
RUN pip install --no-cache-dir uv && uv export --locked --no-dev --no-emit-project -o /tmp/requirements.txt && uv pip install --system --no-cache -r /tmp/requirements.txt
COPY apps/worker/exposure360_worker ./exposure360_worker
USER appuser
CMD ["celery", "-A", "exposure360_worker.tasks.celery", "worker", "--loglevel=INFO"]
