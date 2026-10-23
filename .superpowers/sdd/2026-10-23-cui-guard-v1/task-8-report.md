# Task 8 report
Implemented SessionMap (src/cui_guard/pseudo/mapper.py) with boundary-aware PLACEHOLDER_RE, collision tracking of placeholder tokens from all seen texts, ip cap 65534 (RuntimeError), longest-first echo re-mask skipping placeholder spans, placeholder_for, __len__, lock.
Tests: tests/pseudo/test_mapper.py, 15 passing; ruff clean. Two of my own test expectations were corrected during GREEN.
