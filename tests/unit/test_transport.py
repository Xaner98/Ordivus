"""insecure_transport je Adapter (ohne Verbindung)."""

import pytest

from ordivus.adapters.arcadedb import ArcadeDBAdapter
from ordivus.adapters.clickhouse import ClickHouseAdapter
from ordivus.adapters.mysql import MySQLAdapter
from ordivus.adapters.openbao import OpenBaoAdapter
from ordivus.adapters.postgresql import PostgreSQLAdapter
from ordivus.adapters.redis import RedisAdapter


def ep(**endpoint):
    return {"endpoint": {"host": "h", **endpoint}}


@pytest.mark.parametrize("adapter, spec, insecure", [
    (PostgreSQLAdapter, ep(), True),  # Default prefer
    (PostgreSQLAdapter, ep(tls={"mode": "require"}), True),
    (PostgreSQLAdapter, ep(tls={"mode": "verify-ca"}), False),
    (PostgreSQLAdapter, ep(tls={"mode": "verify-full"}), False),
    (MySQLAdapter, ep(), False),  # Default verify-full
    (MySQLAdapter, ep(tls={"mode": "require"}), True),
    (MySQLAdapter, ep(tls={"mode": "disable"}), True),
    (MySQLAdapter, ep(tls={"mode": "verify-ca"}), False),
    (ClickHouseAdapter, ep(), True),
    (ClickHouseAdapter, ep(tls={}), False),
    (ArcadeDBAdapter, ep(), True),
    (ArcadeDBAdapter, ep(tls={"caFile": "ca.pem"}), False),
    (RedisAdapter, ep(), True),
    (RedisAdapter, ep(tls={}), False),
    (OpenBaoAdapter, {"endpoint": {"url": "http://bao:8200"}}, True),
    (OpenBaoAdapter, {"endpoint": {"url": "https://bao:8200"}}, False),
])
def test_insecure_transport(adapter, spec, insecure):
    assert adapter().insecure_transport(spec) is insecure
