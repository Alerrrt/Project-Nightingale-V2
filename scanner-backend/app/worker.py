from celery import Celery

celery = Celery('app', broker='redis://redis:6379/0')

# Optional: Configure Celery
celery.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
) 