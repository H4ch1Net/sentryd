"""Live capture error handling, the paths that matter without root."""

import pytest

from sentryd.sources.base import SourceError
from sentryd.sources.live import LiveCaptureSource


def test_permission_error_becomes_actionable_message(monkeypatch):
    from scapy.config import conf

    def denied(*args, **kwargs):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(conf, "L2listen", denied)

    with pytest.raises(SourceError, match="needs root"):
        next(LiveCaptureSource(interface="eth0").events())


def test_bad_interface_becomes_source_error(monkeypatch):
    from scapy.config import conf

    def no_such_device(*args, **kwargs):
        raise OSError(19, "No such device")

    monkeypatch.setattr(conf, "L2listen", no_such_device)

    with pytest.raises(SourceError, match="could not open nope0"):
        next(LiveCaptureSource(interface="nope0").events())
