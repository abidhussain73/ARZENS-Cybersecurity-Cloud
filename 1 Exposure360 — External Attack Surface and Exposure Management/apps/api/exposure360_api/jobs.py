from celery import Celery

from .config import Settings


def get_celery_client(settings: Settings) -> Celery:
    return Celery("exposure360_api", broker=settings.redis_url, backend=settings.redis_url)
