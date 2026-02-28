#!/usr/bin/env python3
"""Backward-compatible GUI launcher.

GUI implementation now lives in src/app.py (single unified core).
"""

from app import run_gui


if __name__ == "__main__":
    run_gui()