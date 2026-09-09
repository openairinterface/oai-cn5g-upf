# SPDX-License-Identifier: MIT
"""Unit tests for :mod:`upf_test` -- the OAI UPF adapter.

Everything here encodes something true only of this UPF: its BPF map names and
key layouts, its HTB class-id hash, its log strings. When the UPF changes any of
those, these are the tests that should fail.
"""
