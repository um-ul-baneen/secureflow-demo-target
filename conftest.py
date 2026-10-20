"""
Root conftest.py — inserts every directory matching */src/main/* into sys.path
so that test modules can import application code without package installation.
"""
import sys
import pathlib

_ROOT = pathlib.Path(__file__).parent

for _candidate in _ROOT.rglob("src/main"):
    if _candidate.is_dir():
        _path_str = str(_candidate)
        if _path_str not in sys.path:
            sys.path.insert(0, _path_str)
