"""Deterministic test doubles for the Stage 5 application ports (plan section 11).

Test-resident on purpose: specification section 8 requires ``persistence`` to
implement the repository protocols and the application never to import a
concrete implementation, and ``persistence`` is Stage 8-owned. Nothing under
``crypto_lab`` imports this package.
"""
