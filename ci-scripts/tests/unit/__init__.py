# SPDX-License-Identifier: MIT
"""Unit tests for the test framework itself.

These need no UPF, no root, and no Docker -- only scapy. They exist because a
silent encoding or model bug in the harness would make integration assertions
pass for the wrong reason, which is the worst failure mode a test suite can have.
"""
