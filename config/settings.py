from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Mode
    test_mode: bool = Field(default=True)

    # Email — Phase 2
    gmail_client_id: str = Field(default="")
    gmail_client_secret: str = Field(default="")
    gmail_refresh_token: str = Field(default="")
    approval_email_recipient: str = Field(default="")
    approval_email_sender: str = Field(default="")

    # LinkedIn — Phase 3
    linkedin_client_id: str = Field(default="")
    linkedin_client_secret: str = Field(default="")
    linkedin_access_token: str = Field(default="")
    linkedin_author_urn: str = Field(default="")

    # Anthropic — Phase 4
    anthropic_api_key: str = Field(default="")

    # NVD
    nvd_api_key: str = Field(default="")

    # Storage
    data_dir: Path = Field(default=Path("data"))

    # Logging
    log_level: str = Field(default="INFO")

    # Collection window
    collection_window_hours: int = Field(default=48)

    @property
    def raw_data_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def audit_dir(self) -> Path:
        return self.data_dir / "audit"

    def ensure_dirs(self) -> None:
        for path in (self.raw_data_dir, self.reports_dir, self.audit_dir):
            path.mkdir(parents=True, exist_ok=True)


settings = Settings()
