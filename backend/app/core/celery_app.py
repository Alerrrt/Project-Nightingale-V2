# backend/app/core/celery_app.py
from celery import Celery

# The broker URL points to our Redis service
celery_app = Celery(
    "tasks",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0",
    include=["app.tasks.scan_tasks"] # Point to the file with task definitions
)

celery_app.conf.update(
    task_track_started=True,
)