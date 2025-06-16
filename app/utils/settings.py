import os
from pathlib import Path
from pydantic_settings import BaseSettings
from decouple import config

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseSettings):
    # General
    PYTHON_ENV: str = config("PYTHON_ENV")
    SECRET_KEY: str = config("SECRET_KEY")
    ALGORITHM: str = config("ALGORITHM")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = config("ACCESS_TOKEN_EXPIRE_MINUTES", cast=int)
    JWT_REFRESH_EXPIRY: int = config("JWT_REFRESH_EXPIRY", cast=int)
    APP_URL: str = config("APP_URL")
    DEBUG: bool = config("DEBUG", cast=bool)
    ENVIRONMENT: str = config("ENVIRONMENT")

    # App Info
    APP_NAME: str = config("APP_NAME")
    APP_VERSION: str = config("APP_VERSION")

    # JWT
    JWT_SECRET_KEY: str = config("JWT_SECRET_KEY")

    # Database
    DATABASE_URL: str = config("DATABASE_URL")
    DB_HOST: str = config("DB_HOST")
    DB_PORT: int = config("DB_PORT", cast=int)
    DB_NAME: str = config("DB_NAME")
    DB_USER: str = config("DB_USER")
    DB_TYPE: str = config("DB_TYPE")
    DB_PASSWORD: str = config("DB_PASSWORD")

    # Email
    SMTP_HOST: str = config("SMTP_HOST")
    SMTP_PORT: int = config("SMTP_PORT", cast=int)
    SMTP_USER: str = config("SMTP_USER")
    SMTP_PASSWORD: str = config("SMTP_PASSWORD")
    FROM_EMAIL: str = config("FROM_EMAIL")

    # CORS
    ALLOWED_ORIGINS: str = config("ALLOWED_ORIGINS")

    # File Uploads
    MAX_FILE_SIZE: int = config("MAX_FILE_SIZE", cast=int)
    UPLOAD_DIR: str = config("UPLOAD_DIR")

    # Optional Tool Flag
    @property
    def ACTIVATE_TOOL_TRACKING(self) -> bool:
        return config("ACTIVATE_TOOL_TRACKING", default="True").lower() in {"true", "1", "yes"}

settings = Settings()
