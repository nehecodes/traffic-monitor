"""
config_schema.py — Pydantic models for configuration validation.

Loads config.yaml and .env, validates all values, and provides type-safe
access to configuration throughout the application.
"""

import os
from typing import Optional
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator, ConfigDict
from dotenv import load_dotenv


# ── Pydantic Models ──────────────────────────────────────────────────────────


class LogConfig(BaseModel):
    """Log file paths configuration."""
    
    nginx_access_log: str = Field(
        default="/var/log/nginx/hng-access.log",
        description="Path to Nginx JSON access log"
    )
    audit_log: str = Field(
        default="/var/log/detector/audit.log",
        description="Path to detector audit log"
    )

    @field_validator("nginx_access_log", "audit_log")
    @classmethod
    def validate_path(cls, v: str) -> str:
        """Ensure paths are absolute."""
        if not v:
            raise ValueError("Log path cannot be empty")
        # Convert to absolute path
        return str(Path(v).resolve())


class ThresholdsConfig(BaseModel):
    """Anomaly detection thresholds."""
    
    anomaly_zscore: float = Field(
        default=3.0,
        gt=0.0,
        description="Z-score threshold for anomaly detection"
    )
    anomaly_rate_multiplier: float = Field(
        default=5.0,
        gt=1.0,
        description="Rate multiplier threshold (e.g., 5× baseline mean)"
    )
    error_surge_multiplier: float = Field(
        default=3.0,
        gt=1.0,
        description="Error rate multiplier to trigger tightened thresholds"
    )
    tightened_zscore: float = Field(
        default=2.0,
        gt=0.0,
        description="Tightened z-score threshold when error surge detected"
    )
    tightened_rate_multiplier: float = Field(
        default=3.0,
        gt=1.0,
        description="Tightened rate multiplier when error surge detected"
    )
    min_absolute_rate: float = Field(
        default=10.0,
        ge=0.0,
        description="Minimum req/s before per-IP blocking can occur"
    )
    min_absolute_global_rate: float = Field(
        default=20.0,
        ge=0.0,
        description="Minimum global req/s before global alerts fire"
    )


class WindowsConfig(BaseModel):
    """Time windows for rate calculation and baseline."""
    
    rate_window_seconds: int = Field(
        default=60,
        gt=0,
        le=300,
        description="Sliding window for rate calculation (seconds)"
    )
    baseline_window_minutes: int = Field(
        default=30,
        gt=0,
        le=1440,
        description="Rolling window for baseline calculation (minutes)"
    )
    baseline_recalc_seconds: int = Field(
        default=60,
        gt=0,
        le=600,
        description="Interval between baseline recalculations (seconds)"
    )
    min_baseline_samples: int = Field(
        default=300,
        gt=0,
        description="Minimum samples before detection activates"
    )


class BanConfig(BaseModel):
    """Ban schedule and whitelist configuration."""
    
    schedule_minutes: list[int] = Field(
        default=[10, 30, 120],
        description="Progressive ban durations in minutes (4th+ = permanent)"
    )

    @field_validator("schedule_minutes")
    @classmethod
    def validate_schedule(cls, v: list[int]) -> list[int]:
        """Ensure schedule is non-empty and values are positive."""
        if not v:
            raise ValueError("Ban schedule cannot be empty")
        if any(x <= 0 for x in v):
            raise ValueError("Ban durations must be positive")
        if v != sorted(v):
            raise ValueError("Ban schedule must be in ascending order")
        return v


class WhitelistConfig(BaseModel):
    """IP whitelist configuration."""
    
    ips: list[str] = Field(
        default_factory=list,
        description="IPs that are never blocked"
    )

    @field_validator("ips")
    @classmethod
    def validate_ips(cls, v: list[str]) -> list[str]:
        """Filter out empty strings and validate IP format."""
        # Filter out empty strings
        ips = [ip.strip() for ip in v if ip and ip.strip()]
        
        # Basic IP validation (IPv4)
        for ip in ips:
            parts = ip.split(".")
            if len(parts) != 4:
                raise ValueError(f"Invalid IP address format: {ip}")
            try:
                if not all(0 <= int(part) <= 255 for part in parts):
                    raise ValueError(f"Invalid IP address octets: {ip}")
            except ValueError:
                raise ValueError(f"Invalid IP address: {ip}")
        
        return ips


class DashboardConfig(BaseModel):
    """Dashboard server configuration."""
    
    host: str = Field(
        default="0.0.0.0",
        description="Dashboard bind host"
    )
    port: int = Field(
        default=8080,
        gt=0,
        le=65535,
        description="Dashboard port"
    )
    refresh_interval_seconds: int = Field(
        default=3,
        gt=0,
        le=60,
        description="Dashboard refresh interval"
    )


class Config(BaseModel):
    """Complete application configuration."""
    
    model_config = ConfigDict(extra="forbid")  # Reject unknown fields
    
    log: LogConfig
    thresholds: ThresholdsConfig
    windows: WindowsConfig
    ban: BanConfig
    whitelist: WhitelistConfig
    dashboard: DashboardConfig
    
    # Secrets loaded from environment
    slack_webhook_url: Optional[str] = Field(
        default=None,
        description="Slack webhook URL (loaded from SLACK_WEBHOOK_URL env var)"
    )

    @field_validator("slack_webhook_url")
    @classmethod
    def validate_webhook(cls, v: Optional[str]) -> Optional[str]:
        """Validate webhook URL format if provided."""
        if v and not v.startswith("https://hooks.slack.com/"):
            raise ValueError(
                "Invalid Slack webhook URL format. "
                "Expected: https://hooks.slack.com/services/..."
            )
        return v


# ── Configuration Loader ──────────────────────────────────────────────────────


def load_config(config_path: str) -> Config:
    """
    Load and validate configuration from YAML file and environment variables.
    
    Priority (highest to lowest):
    1. Environment variables (SLACK_WEBHOOK_URL, etc.)
    2. config.yaml values
    3. Default values from Pydantic models
    
    Args:
        config_path: Path to config.yaml file
        
    Returns:
        Validated Config object
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If configuration validation fails
        yaml.YAMLError: If YAML parsing fails
    """
    # Load environment variables from .env file if present
    env_path = Path(config_path).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
        print(f"[config] Loaded environment from {env_path}", flush=True)
    
    # Load YAML config
    if not Path(config_path).exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    with open(config_path) as f:
        raw_config = yaml.safe_load(f)
    
    if raw_config is None:
        raw_config = {}
    
    # Inject environment variables
    raw_config["slack_webhook_url"] = os.getenv("SLACK_WEBHOOK_URL")
    
    # Allow environment overrides for specific fields
    if os.getenv("NGINX_ACCESS_LOG"):
        raw_config.setdefault("log", {})["nginx_access_log"] = os.getenv("NGINX_ACCESS_LOG")
    if os.getenv("AUDIT_LOG"):
        raw_config.setdefault("log", {})["audit_log"] = os.getenv("AUDIT_LOG")
    if os.getenv("DASHBOARD_HOST"):
        raw_config.setdefault("dashboard", {})["host"] = os.getenv("DASHBOARD_HOST")
    if os.getenv("DASHBOARD_PORT"):
        raw_config.setdefault("dashboard", {})["port"] = int(os.getenv("DASHBOARD_PORT"))
    
    # Validate and construct Config object
    try:
        config = Config(**raw_config)
        print("[config] Configuration validated successfully", flush=True)
        return config
    except Exception as e:
        print(f"[config] Configuration validation failed: {e}", flush=True)
        raise


# ── Convenience functions ─────────────────────────────────────────────────────


def get_config() -> Config:
    """
    Load configuration from default location.
    Intended for use by main.py.
    """
    config_path = Path(__file__).parent.parent / "config.yaml"
    return load_config(str(config_path))
