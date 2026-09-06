"""Strict explicit configuration boundary for the research core."""

from crypto_lab.configuration.loader import ConfigurationError, load_configuration
from crypto_lab.configuration.models import (
    ApplicationConfig,
    CliOverrides,
    ConfigurationLayer,
)
from crypto_lab.configuration.retry_policy import retry_policy_from_config
from crypto_lab.configuration.snapshot import (
    ConfigSnapshot,
    configuration_audit_hash,
    material_base_configuration_hash,
    snapshot_configuration,
)
from crypto_lab.domain.lifecycle import RetryTerminalState

__all__ = (
    "ApplicationConfig",
    "CliOverrides",
    "ConfigSnapshot",
    "ConfigurationError",
    "ConfigurationLayer",
    "RetryTerminalState",
    "configuration_audit_hash",
    "load_configuration",
    "material_base_configuration_hash",
    "retry_policy_from_config",
    "snapshot_configuration",
)
