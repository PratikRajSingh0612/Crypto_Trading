"""The packaged Alembic script directory (plan sections 2.3, 6.4, 6.7).

``env.py``, ``script.py.mako`` and ``versions/`` live inside the package so the
pinned hatch configuration ships them with the wheel and the sdist; there is no
``alembic.ini`` and no root-level migration directory. The runner
(``crypto_lab.persistence.migration_runner``) resolves this directory from its
own location and is the only caller.
"""
