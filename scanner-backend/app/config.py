import os

class Settings:
    PROJECT_NAME: str = "Project Nightingale"
    CELERY_BROKER_URL: str = os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/0')
    CELERY_RESULT_BACKEND: str = os.getenv('CELERY_RESULT_BACKEND', 'redis://redis:6379/0')
    DATABASE_URL: str = os.getenv('DATABASE_URL', 'sqlite+aiosqlite:///./nightingale.db')

settings = Settings()