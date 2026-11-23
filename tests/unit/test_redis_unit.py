"""Redis-Adapter ohne Server: Versionsprüfung und Persistenz-Vorbedingungen in ``connect`` (Stub-Client)."""

import pytest

redis = pytest.importorskip("redis")

from ordivus.adapters import redis as adapter_mod  # noqa: E402
from ordivus.adapters.base import PermanentError, Secret  # noqa: E402
from ordivus.adapters.redis import RedisAdapter  # noqa: E402

TARGET = {"endpoint": {"host": "127.0.0.1"}, "username": "admin"}


def stub(monkeypatch, info, aclfile=""):
    class Client:
        def __init__(self, **kwargs):
            pass

        def ping(self):
            return True

        def info(self, section):
            return info

        def config_get(self, name):
            return {"aclfile": aclfile}

        def close(self):
            pass

    monkeypatch.setattr(redis, "Redis", Client)


def connect(**target):
    with RedisAdapter().connect({**TARGET, **target}, Secret("pw"), write=True) as session:
        return RedisAdapter().server_version(session)


@pytest.mark.parametrize("info, shown", [
    ({"redis_version": "8.0.2"}, "Redis 8.0.2"),
    ({"redis_version": "7.0.15"}, "Redis 7.0.15"),
    ({"redis_version": "7.2.4", "server_name": "valkey", "valkey_version": "8.1.0"}, "Valkey 8.1.0"),
])
def test_supported_versions(monkeypatch, info, shown):
    stub(monkeypatch, info)
    assert connect() == shown


@pytest.mark.parametrize("version", ["6.2.24", "5.0.14", "", None])
def test_old_or_unknown_versions_rejected(monkeypatch, version):
    stub(monkeypatch, {"redis_version": version} if version is not None else {})
    with pytest.raises(PermanentError, match="is not supported \\(minimum Redis 7.0\\)"):
        connect()


def test_config_rewrite_rejected_with_aclfile(monkeypatch):
    """Regression: CONFIG REWRITE schreibt keine Benutzer, wenn aclfile gesetzt ist (Neustart verliert sie)."""
    stub(monkeypatch, {"redis_version": "8.0.2", "config_file": "/etc/redis.conf"}, aclfile="/data/users.acl")
    with pytest.raises(PermanentError, match="use persist: aclSave"):
        connect(persist="configRewrite")
    assert connect(persist="aclSave") == "Redis 8.0.2"


def test_getuser_reply_shapes():
    resp3 = {"flags": ["on"], "keys": "~*", "selectors": [{"commands": "+get", "keys": "~a"}]}
    resp2 = ["flags", ["on"], "keys", "~*", "selectors", [["commands", "+get", "keys", "~a"]]]

    class Client:
        def __init__(self, reply):
            self.reply = reply

        def execute_command(self, *args):
            return self.reply

    assert adapter_mod._getuser(Client(resp2), "u") == adapter_mod._getuser(Client(resp3), "u") == resp3
    assert adapter_mod._getuser(Client(None), "u") is None
