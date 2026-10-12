import io
import json
import urllib.error
from unittest import mock

import pytest

import vault_config
from vault_config.testing import fake


@pytest.fixture
def env(tmp_path, monkeypatch):
    (tmp_path / "token").write_text("jwt")
    (tmp_path / "namespace").write_text("ns")
    monkeypatch.setenv("VAULT_ADDR", "http://vault")
    monkeypatch.setenv("VAULT_ROLE", "app")
    monkeypatch.setenv("VAULT_SECRET_NAME", "app-config")
    monkeypatch.setenv("VAULT_AUTH_TOKEN_PATH", str(tmp_path))
    vault_config.reload()
    yield
    vault_config.reload()


def _serve(*payloads):
    """Simula Vault: cada llamada devuelve el siguiente payload o un código HTTP."""
    queue = list(payloads)

    def fake_open(req, timeout=None):
        item = queue.pop(0)
        if isinstance(item, int):
            raise urllib.error.HTTPError(req.full_url, item, "err", {}, None)
        return io.BytesIO(json.dumps(item).encode())

    return mock.patch("urllib.request.urlopen", side_effect=fake_open)


LOGIN = {"auth": {"client_token": "t"}}
DATA = {"data": {"data": {"DB_HOST": "db", "DEBUG": "false", "PORT": 8080}}}


def test_un_login_y_una_lectura(env):
    with _serve(LOGIN, DATA) as m:
        for _ in range(100):
            assert vault_config.get("DB_HOST") == "db"
        assert vault_config.get_bool("DEBUG") is False
        assert vault_config.get_int("PORT") == 8080
    assert m.call_count == 2


def test_token_vencido_reintenta_una_vez(env):
    with _serve(LOGIN, 403, LOGIN, DATA) as m:
        assert vault_config.get("DB_HOST") == "db"
    assert m.call_count == 4


def test_secreto_inexistente(env):
    with _serve(LOGIN, 404):
        with pytest.raises(vault_config.VaultConfigError, match="No existe"):
            vault_config.get("DB_HOST")


def test_falta_puntero(monkeypatch):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.setenv("VAULT_SECRET_NAME", "x")
    vault_config.reload()
    with pytest.raises(vault_config.VaultConfigError, match="VAULT_ADDR"):
        vault_config.get("A")


def test_error_no_expone_valores():
    with fake({"A": "valor-secreto", "B": "quizas"}):
        with pytest.raises(vault_config.VaultConfigError) as err:
            vault_config.get("C")
        assert "valor-secreto" not in str(err.value)
        with pytest.raises(vault_config.VaultConfigError) as err:
            vault_config.get_bool("B")
        assert "quizas" not in str(err.value)


def test_fake_sin_red():
    with fake({"PORT": "8080"}):
        assert vault_config.get_int("PORT") == 8080
