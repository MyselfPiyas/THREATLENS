from functools import lru_cache
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "THREATLENS API"
    app_env: str = "development"
    log_level: str = "INFO"
    frontend_allowed_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    supabase_url: str | None = None
    supabase_publishable_key: SecretStr | None = None
    supabase_anon_key: SecretStr | None = None
    supabase_secret_key: SecretStr | None = None
    supabase_service_role_key: SecretStr | None = None
    openrouter_api_key: SecretStr | None = None
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_model: str | None = None
    openrouter_site_url: str | None = None
    openrouter_app_name: str = "THREATLENS"
    llm_request_timeout_seconds: float = Field(default=15.0, gt=0, le=60)

    # Trust Passports are off-chain canonical JSON reports with SHA-256 hashes.
    passport_scanner_version: str = "0.1.0"
    passport_report_version: str = "1.0"

    url_scan_max_url_length: int = Field(default=2048, ge=256, le=8192)
    url_scan_connect_timeout_seconds: float = Field(default=3.0, gt=0, le=10)
    url_scan_total_timeout_seconds: float = Field(default=15.0, gt=0, le=45)
    url_scan_job_timeout_seconds: float = Field(default=60.0, gt=0, le=180)
    url_scan_max_response_bytes: int = Field(default=16384, ge=1024, le=65536)
    url_scan_max_redirects: int = Field(default=5, ge=0, le=10)
    url_scan_suspicious_score: int = Field(default=25, ge=1, le=100)
    url_scan_high_risk_score: int = Field(default=60, ge=2, le=100)
    url_scan_weight_punycode: int = Field(default=22, ge=0, le=100)
    url_scan_weight_deep_subdomain: int = Field(default=12, ge=0, le=100)
    url_scan_weight_sensitive_path: int = Field(default=10, ge=0, le=100)
    url_scan_weight_http: int = Field(default=12, ge=0, le=100)
    url_scan_weight_redirect_limit: int = Field(default=20, ge=0, le=100)
    url_scan_weight_redirect_chain: int = Field(default=15, ge=0, le=100)
    url_scan_weight_blocked_redirect: int = Field(default=60, ge=0, le=100)
    url_scan_confirmed_min_confidence: float = Field(default=0.95, ge=0.9, le=1)
    url_scan_trusted_threat_sources: str = "urlhaus,openphish,phishtank,threatfox,google-safe-browsing"

    @model_validator(mode="after")
    def validate_url_scan_thresholds(self) -> "Settings":
        if self.url_scan_high_risk_score <= self.url_scan_suspicious_score:
            raise ValueError("URL_SCAN_HIGH_RISK_SCORE must be greater than URL_SCAN_SUSPICIOUS_SCORE.")
        return self

    @field_validator("supabase_url")
    @classmethod
    def validate_supabase_url(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return value

        normalized = value.strip()
        parsed = urlsplit(normalized)
        try:
            parsed.port
        except ValueError as error:
            raise ValueError("SUPABASE_URL must be a valid HTTP(S) origin.") from error

        local_http_host = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if (
            parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or not parsed.hostname
            or not (parsed.scheme == "https" or (parsed.scheme == "http" and local_http_host))
        ):
            raise ValueError("SUPABASE_URL must use HTTPS, except for a loopback local Supabase URL.")
        return normalized.rstrip("/")

    @field_validator("frontend_allowed_origins")
    @classmethod
    def validate_frontend_allowed_origins(cls, value: str) -> str:
        origins = [origin.strip() for origin in value.split(",") if origin.strip()]
        normalized_origins: list[str] = []
        for origin in origins:
            parsed = urlsplit(origin)
            try:
                parsed.port
            except ValueError as error:
                raise ValueError("FRONTEND_ALLOWED_ORIGINS must contain valid HTTP(S) origins.") from error
            if (
                origin == "*"
                or parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or not parsed.hostname
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
                or parsed.username
                or parsed.password
            ):
                raise ValueError("FRONTEND_ALLOWED_ORIGINS must contain exact HTTP(S) origins, not paths or wildcards.")
            normalized_origins.append(f"{parsed.scheme}://{parsed.netloc.lower()}")
        return ",".join(normalized_origins)

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.frontend_allowed_origins.split(",") if origin.strip()]

    @property
    def supabase_is_configured(self) -> bool:
        return bool(self.supabase_url and self.supabase_url.strip() and self.supabase_key_value)

    @property
    def supabase_key_value(self) -> str | None:
        for key in (self.supabase_publishable_key, self.supabase_anon_key):
            if key and key.get_secret_value().strip():
                return key.get_secret_value()
        return None

    @property
    def supabase_admin_key_value(self) -> str | None:
        for key in (self.supabase_secret_key, self.supabase_service_role_key):
            if key and key.get_secret_value().strip():
                return key.get_secret_value()
        return None


@lru_cache
def get_settings() -> Settings:
    return Settings()
