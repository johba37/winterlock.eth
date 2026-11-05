"""Tests keep device anchors (winterlock_signer/device.py) in a temporary directory, never in the user's own."""
import atexit
import os
import shutil
import tempfile

if not os.environ.get("WINTERLOCK_ANCHOR_DIR"):
    _anchors = tempfile.mkdtemp(prefix="winterlock-anchors-")
    os.environ["WINTERLOCK_ANCHOR_DIR"] = _anchors
    atexit.register(shutil.rmtree, _anchors, True)
os.environ.pop("WINTERLOCK_PASSPHRASE", None)
