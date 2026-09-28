"""Settings are read from environment variables so the same image can run
in dev, staging and prod with different config."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    app_env: str
    app_version: str
    database_path: str
    analyst_api_key: str
    admin_api_key: str
    # how many bad API keys from one IP (inside the window) counts as brute force
    brute_force_threshold: int
    brute_force_window_seconds: int


def load_settings() -> Settings:
    return Settings(
        app_env=os.getenv("APP_ENV", "dev"),
        app_version=os.getenv("APP_VERSION", "0.0.0-dev"),
        database_path=os.getenv("DATABASE_PATH", "secureflow.db"),
        analyst_api_key=os.getenv("ANALYST_API_KEY", "analyst-dev-key"),
        admin_api_key=os.getenv("ADMIN_API_KEY", "admin-dev-key"),
        brute_force_threshold=int(os.getenv("BRUTE_FORCE_THRESHOLD", "5")),
        brute_force_window_seconds=int(os.getenv("BRUTE_FORCE_WINDOW", "60")),
    )
