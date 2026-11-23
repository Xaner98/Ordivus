"""Adapter-Vertrag: api_version-Prüfung der Registry, serverVersion im Report, gemeinsame Helfer."""

import http.client
import io
from importlib.metadata import EntryPoint

import pytest
from conftest import doc

from ordivus import adapters, net, openbao_http
from ordivus.adapters import arcadedb, common, openbao
from ordivus.adapters.base import API_VERSION, AuthorizationError, PermanentError, Secret, TransientError
from ordivus.adapters.fake import FakeAdapter
from ordivus.core import config, engine, report
from ordivus.core.policy import OperatorPolicy


class Old(FakeAdapter):
    id = "old"
    api_version = None


class Future(FakeAdapter):
    id = "future"
    api_version = API_VERSION + 1


class NoKinds(FakeAdapter):
    id = "nokinds"
    kinds = ()


class Good(FakeAdapter):
    id = "good"


def test_register_accepts_only_current_contract(caplog):
    assert isinstance(adapters.register(Good), Good)
    for cls in (Old, Future, NoKinds, object, "x"):
        assert adapters.register(cls) is None
    assert "built for contract None, engine supports 1" in caplog.text
    assert f"built for contract {API_VERSION + 1}" in caplog.text
    assert "kinds must be" in caplog.text and "not a subclass" in caplog.text


def test_load_skips_broken_plugins(monkeypatch, caplog):
    classes = {"old": Old, "nokinds": NoKinds, "junk": 42, "fake": FakeAdapter}
    eps = [EntryPoint(n, f"plugin:{n}", "ordivus.adapters") for n in classes]
    monkeypatch.setattr(EntryPoint, "load", lambda self: classes[self.name])
    monkeypatch.setattr(adapters, "entry_points", lambda group: eps)
    monkeypatch.setattr(adapters, "_registry", {})
    monkeypatch.setattr(adapters, "_loaded", False)
    assert adapters.all_kinds() == frozenset(FakeAdapter.kinds)
    assert adapters.get("old") is None and "'old' (plugin:old) skipped: built for contract None" in caplog.text


def test_server_version_in_report(cfg, monkeypatch):
    monkeypatch.setattr(FakeAdapter, "server_version", lambda self, session: "Fake 1.2")
    rep = engine.run("plan", config.load(cfg(doc("FakeItem", "a", targetRef="t1"))), OperatorPolicy())
    assert rep["targets"][0]["serverVersion"] == "Fake 1.2"
    assert "target t1 [fake] (Fake 1.2): drift_detected" in report.render_human(rep)


def test_openbao_version_check(caplog):
    assert openbao.server_version({"version": "2.7.3", "commit_date": "x"}) == "OpenBao 2.7.3"
    with pytest.raises(PermanentError, match=r"OpenBao 1.9.0 is not supported \(minimum 2.0\)"):
        openbao.server_version({"version": "1.9.0", "commit_date": "x"})
    assert openbao.server_version({"version": "1.15.2", "build_date": "x"}) == "Vault 1.15.2"
    assert "Vault" in caplog.text
    assert openbao.server_version({}) is None


def test_tls_context_bad_cafile(tmp_path):
    with pytest.raises(PermanentError, match="cannot load tls.caFile"):
        common.tls_context({"caFile": str(tmp_path / "missing.pem")})
    (tmp_path / "bad.pem").write_text("not a certificate")
    with pytest.raises(PermanentError, match="cannot load tls.caFile"):
        common.tls_context({"caFile": str(tmp_path / "bad.pem")})
    assert common.tls_context(None).check_hostname


def test_openbao_bad_cafile_is_target_error(tmp_path):
    with pytest.raises(PermanentError), openbao.OpenBaoAdapter().connect(
            {"endpoint": {"url": "https://bao"}, "tls": {"caFile": str(tmp_path / "x")}}, Secret("t"), False):
        pass


@pytest.mark.parametrize("status,error", [(500, TransientError), (503, TransientError), (429, TransientError),
                                          (401, AuthorizationError), (403, AuthorizationError),
                                          (400, PermanentError), (404, PermanentError)])
def test_status_error(status, error):
    assert type(net.status_error(status, "x")) is error
    with pytest.raises(error):
        openbao_http.check(status, {"errors": "not a list"}, "x")
    with pytest.raises(error):
        arcadedb._check(status, None, "x")


def test_incomplete_read_is_transient():
    class Broken(io.BytesIO):
        def read(self, n=-1):
            raise http.client.IncompleteRead(b"")
    with pytest.raises(TransientError):
        net.read(Broken())


def test_validate_endpoint():
    assert common.validate_endpoint({"host": "db", "port": 5432, "tls": {"caFile": "/ca"}}) == []
    assert common.validate_endpoint({"host": "::1"}) == []
    assert common.validate_endpoint({"host": "a@b", "port": 0, "tls": {"caFile": 1, "x": 1}, "y": 1}) == [
        "unknown field spec.endpoint.y",
        "spec.endpoint.host must be a host name or IP address (no '/', '\\', '@', '?', '#', '[', ']', whitespace)",
        "spec.endpoint.port must be an integer 1-65535", "unknown field spec.endpoint.tls.x",
        "spec.endpoint.tls.caFile must be a non-empty string"]
    assert common.validate_endpoint({"host": "h", "tls": []}) == ["spec.endpoint.tls must be a mapping"]
    assert common.validate_endpoint(None) == ["spec.endpoint must be a mapping"]


def test_in_scope():
    assert common.in_scope(None, "users", "a")
    assert common.in_scope({"users": {"include": ["app_*"]}}, "users", "app_x")
    assert not common.in_scope({"users": {"include": ["app_*"]}}, "users", "APP_x")


@pytest.mark.parametrize("body", [{}, {"data": None}, {"data": {"keys": None}}, {"data": {"keys": [1]}}])
def test_openbao_discover_rejects_bad_shapes(monkeypatch, body):
    monkeypatch.setattr(openbao_http, "request", lambda *a, **k: (200, body))
    session = openbao.Session("https://bao", "t", None, False, frozenset())
    with pytest.raises(PermanentError, match="unexpected response"):
        openbao.OpenBaoAdapter().discover(session, openbao.KIND, None)


@pytest.mark.parametrize("kind,payload", [("Database", None), ("Database", {"result": None}),
                                          ("Database", {"result": [1]}), ("DatabaseUser", {"result": [{}]}),
                                          ("DatabaseUser", {"result": [{"name": "u", "databases": {"d": 1}}]})])
def test_arcadedb_discover_rejects_bad_shapes(monkeypatch, kind, payload):
    monkeypatch.setattr(arcadedb, "_call", lambda *a: (200, payload))
    session = arcadedb.Session("http://h:2480", None, "root", "Basic x", False)
    with pytest.raises(PermanentError, match="unexpected response"):
        arcadedb.ArcadeDBAdapter().discover(session, kind, None)
