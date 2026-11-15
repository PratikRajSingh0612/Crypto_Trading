"""Offline historical candle data: the bounded slices of Project 2.

The package reads one local ``ohlcv-csv/1`` input (``candle_csv``) or one
local, already extracted ``binance-spot-kline-csv/1`` input with an explicitly
declared timestamp unit (``binance_kline_csv``, the second slice), validates
the rows under the plan's section 4 rules with explicit missing and duplicate
intervals (``validation``), writes the interim normalized container with its
SHA-256 checksums and digests the raw input bytes (``normalize``), builds the
core ``DatasetDescriptor`` and ``DatasetPartition`` metadata with the core's
own content identity (``metadata``) and exposes the ``normalize`` command that
composes those steps into an output directory (``cli``, run as
``python -m crypto_lab_offline_data`` through ``__main__``); refusals are the
core diagnostics of ``diagnostics`` and every identifier and instant comes from
the injected providers of ``providers``. The package imports nothing at this
level so that importing it performs no work.
"""

__version__ = "0.1.0"
