import pytest

from ordivus import adapters
from ordivus.adapters.fake import FakeAdapter


@pytest.fixture(autouse=True)
def fake():
    adapters.register(FakeAdapter)
    FakeAdapter.reset()
    yield FakeAdapter
    FakeAdapter.reset()


def doc(kind, name, **spec):
    return {"apiVersion": "ordivus.dev/v1alpha1", "kind": kind, "metadata": {"name": name}, "spec": spec}


@pytest.fixture
def cfg(tmp_path):
    """Schreibt eine Fake-Konfiguration (Target t1 → Instanz i1, File-Provider) plus `extra` Dokumente."""
    import json

    secrets = tmp_path / "secrets"
    secrets.mkdir()

    def write(*extra, base=True):
        directory = tmp_path / "config"
        directory.mkdir(exist_ok=True)
        for f in directory.iterdir():
            f.unlink()
        docs = [doc("Target", "t1", adapter="fake", instance="i1"),
                doc("CredentialProvider", "files", type="file", directory=str(secrets))] if base else []
        for i, d in enumerate(docs + list(extra)):
            (directory / f"{i:02}.json").write_text(json.dumps(d))
        return directory

    write.secrets = secrets
    return write
