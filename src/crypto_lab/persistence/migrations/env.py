"""The Alembic environment of the packaged script directory (plan 6.4, reading 16).

Alembic executes this module when it runs a migration; the fresh-import probe of
``tests/unit/test_package_layout.py`` imports it as a plain module. The module
therefore runs migrations only when the Alembic proxy is established: Alembic
installs ``config`` on ``alembic.context`` inside ``EnvironmentContext.__enter__``
and removes it afterwards, so outside a run the attribute access raises
``AttributeError``, which is caught to decide. ``run_migrations`` configures the
context with the declarative metadata, ``render_as_batch=True`` and
``transaction_per_migration=True`` over the connection the runner placed in
``config.attributes["connection"]``; it imports ``sqlalchemy`` (typing),
``alembic.context`` (aliased, because the Stage 4 bare-name scan forbids the
identifier ``context``) and the schema module, nothing else. It reads no
environment and configures no logging.
"""

from __future__ import annotations

from alembic import context as migration_context
from sqlalchemy.engine import Connection

from crypto_lab.persistence import schema

__all__ = ["run_migrations"]


def run_migrations(connection: Connection) -> None:
    """Run every pending revision on ``connection``, one transaction per revision."""
    migration_context.configure(
        connection=connection,
        target_metadata=schema.metadata,
        render_as_batch=True,
        transaction_per_migration=True,
    )
    with migration_context.begin_transaction():
        migration_context.run_migrations()


def _established_connection() -> Connection | None:
    """The runner's connection when Alembic has established its proxy, else ``None``."""
    try:
        config = migration_context.config
    except AttributeError:
        return None
    connection = config.attributes.get("connection")
    if not isinstance(connection, Connection):
        raise TypeError("the migration runner must supply a SQLAlchemy connection")
    return connection


_connection = _established_connection()
if _connection is not None:
    run_migrations(_connection)
