"""The revision modules of the packaged script directory (plan 6.4, reading 17).

Alembic's revision-file discovery ignores ``__init__.py``; the marker exists so
every revision module is importable for the Stage 3 source-file guard, the
fresh-import layout probe and strict mypy (reading 18).
"""
