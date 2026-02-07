from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import urlparse


ENV_QA = "qa"
ENV_PROD = "prod"
ENV_UNKNOWN = "unknown"
DEFAULT_PACER_AUTH_BASE_URL = "https://qa-login.uscourts.gov"
DEFAULT_PCL_BASE_URL = "https://qa-pcl.uscourts.gov/pcl-public-api/rest"
DEFAULT_PACER_AUTH_BASE_URL_PROD = "https://pacer.login.uscourts.gov"
DEFAULT_PCL_BASE_URL_PROD = "https://pcl.uscourts.gov/pcl-public-api/rest"


@dataclass(frozen=True)
class PacerEnvironmentConfig:
    pacer_auth_base_url: str
    pcl_base_url: str
    auth_env: str
    pcl_env: str
    mismatch: bool
    mismatch_reason: Optional[str]

    def as_dict(self) -> Dict[str, Optional[str]]:
        return {
            "pacer_auth_base_url": self.pacer_auth_base_url,
            "pcl_base_url": self.pcl_base_url,
            "auth_env": self.auth_env,
            "pcl_env": self.pcl_env,
            "mismatch": self.mismatch,
            "mismatch_reason": self.mismatch_reason,
        }


def _extract_host(base_url: str) -> str:
    normalized = (base_url or "").strip()
    if not normalized:
        return ""
    parsed = urlparse(normalized if "://" in normalized else f"//{normalized}")
    host = parsed.netloc or parsed.path.split("/")[0]
    return host.lower()


def _host_matches(host: str, expected: str) -> bool:
    host = (host or "").strip().lower()
    expected = (expected or "").strip().lower()
    if not host or not expected:
        return False
    return host == expected or host.startswith(f"{expected}:")


def infer_pacer_env(base_url: str) -> str:
    host = _extract_host(base_url)
    if "qa-" in host:
        return ENV_QA
    if "pacer.login" in host or "pcl.uscourts.gov" in host:
        return ENV_PROD
    return ENV_UNKNOWN


def pacer_env_label(env: str) -> str:
    if env == ENV_QA:
        return "QA"
    if env == ENV_PROD:
        return "Production"
    return "Unknown"


def pacer_env_billable(env: str) -> Optional[bool]:
    if env == ENV_QA:
        return False
    if env == ENV_PROD:
        return True
    return None


def pacer_env_host(base_url: str) -> str:
    return _extract_host(base_url)


def _mismatch_reason(auth_env: str, pcl_env: str) -> Optional[str]:
    if auth_env == ENV_PROD and pcl_env == ENV_QA:
        return (
            "You are calling QA PCL but authenticating in Production. "
            "Use QA credentials and PACER_AUTH_BASE_URL=https://qa-login.uscourts.gov, "
            "or switch PCL_BASE_URL to https://pcl.uscourts.gov/pcl-public-api/rest."
        )
    if auth_env == ENV_QA and pcl_env == ENV_PROD:
        return (
            "You are calling Production PCL but authenticating in QA. "
            "Use Production credentials and PACER_AUTH_BASE_URL=https://pacer.login.uscourts.gov, "
            "or switch PCL_BASE_URL to https://qa-pcl.uscourts.gov/pcl-public-api/rest."
        )
    if auth_env != pcl_env:
        return "PACER auth and PCL environments do not match."
    return None


def build_pacer_environment_config(
    pacer_auth_base_url: str, pcl_base_url: str
) -> PacerEnvironmentConfig:
    auth_env = infer_pacer_env(pacer_auth_base_url)
    pcl_env = infer_pacer_env(pcl_base_url)
    mismatch = auth_env != ENV_UNKNOWN and pcl_env != ENV_UNKNOWN and auth_env != pcl_env
    mismatch_reason = _mismatch_reason(auth_env, pcl_env) if mismatch else None
    return PacerEnvironmentConfig(
        pacer_auth_base_url=pacer_auth_base_url,
        pcl_base_url=pcl_base_url,
        auth_env=auth_env,
        pcl_env=pcl_env,
        mismatch=mismatch,
        mismatch_reason=mismatch_reason,
    )


def validate_pacer_environment_config(
    pacer_auth_base_url: str, pcl_base_url: str
) -> PacerEnvironmentConfig:
    config = build_pacer_environment_config(pacer_auth_base_url, pcl_base_url)
    auth_host = _extract_host(pacer_auth_base_url)
    pcl_host = _extract_host(pcl_base_url)
    if _host_matches(pcl_host, "qa-pcl.uscourts.gov") and not _host_matches(
        auth_host, "qa-login.uscourts.gov"
    ):
        raise ValueError(_mismatch_reason(ENV_PROD, ENV_QA) or "")
    if _host_matches(pcl_host, "pcl.uscourts.gov") and not _host_matches(
        auth_host, "pacer.login.uscourts.gov"
    ):
        raise ValueError(_mismatch_reason(ENV_QA, ENV_PROD) or "")
    if config.mismatch and config.mismatch_reason:
        raise ValueError(config.mismatch_reason)
    return config
