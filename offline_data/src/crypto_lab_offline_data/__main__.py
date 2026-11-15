"""Execute the offline-data command line as ``python -m crypto_lab_offline_data``."""

from crypto_lab_offline_data.cli import normalize_command
from crypto_lab_offline_data.providers import SystemClock, Uuid4IdProvider

if __name__ == "__main__":
    raise SystemExit(
        normalize_command(None, ids=Uuid4IdProvider(), clock=SystemClock())
    )
