from celery import Celery
import os

broker_url = os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/0')
result_backend = os.getenv('CELERY_RESULT_BACKEND', 'redis://redis:6379/0')

celery_app = Celery('tasks', broker=broker_url, backend=result_backend)
celery_app.config_from_object('app.config', namespace='CELERY')