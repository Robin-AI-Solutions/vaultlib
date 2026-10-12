# Requerimiento: librería `vault-config`

## Objetivo

Librería Python pequeña que encapsula la lectura de configuración desde Vault. Las apps la importan y nunca usan `os.environ` ni `os.getenv` en su propio código: la lectura de los punteros `VAULT_*` vive solo dentro de la librería.

## Uso

```python
from vault_config import get, get_bool, get_int

DB_HOST = get("DB_HOST")
DEBUG = get_bool("DEBUG")
PORT = get_int("PORT")
OTRO = get("API_KEY", secret_name="otro-secreto")
```

- `get(key, secret_name=None)`: devuelve el campo como texto. Sin `secret_name` usa `VAULT_SECRET_NAME`.
- `get_bool` / `get_int`: convierten el valor (el texto `"false"` es verdadero en Python, por eso existe `get_bool`).
- `reload()`: descarta la caché y vuelve a leer de Vault.
- Errores: `VaultConfigError`, que nombra el puntero o la clave que falta y nunca muestra valores ni el token.

## Punteros (únicas variables de entorno)

| Variable | Obligatoria | Por defecto |
|----------|-------------|-------------|
| `VAULT_ADDR` | Sí | — |
| `VAULT_ROLE` | Sí | — |
| `VAULT_SECRET_NAME` | Sí, salvo que se pase `secret_name` | — |
| `VAULT_KV_MOUNT` | No | `secret` |
| `VAULT_AUTH_TOKEN_PATH` | No | `/var/run/secrets/kubernetes.io/serviceaccount` |

## Comportamiento

1. Login por Kubernetes con el JWT del service account y lectura KV v2 en `{mount}/data/{namespace}/{secret_name}`.
2. Caché: un login y una lectura por secreto durante la vida del proceso.
3. Si Vault responde 403 (token vencido), hace login de nuevo y reintenta una vez.
4. Timeout de 5 segundos por llamada.
5. Sin valores por defecto ni respaldo a variables de entorno: si falta algo, falla.
6. Solo librería estándar, Python 3.10+.

## Pruebas en las apps

```python
from vault_config.testing import fake

with fake({"DB_HOST": "localhost", "DEBUG": "false"}):
    ...
```

Reemplaza Vault por un diccionario, sin red. Solo se activa desde código, nunca por variable de entorno.

## Publicación e instalación

1. Subir a un repo de GitHub con la estructura de abajo.
2. Proteger la rama principal y publicar con tag (`v0.1.0`).
3. Instalar fijado al tag:

   ```
   pip install "git+https://github.com/tuorg/vault-config@v0.1.0"
   ```

   o en `requirements.txt`:

   ```
   tuorg-vault-config @ git+https://github.com/tuorg/vault-config@v0.1.0
   ```

Cambiar `tuorg` por el nombre de la organización.

## Criterios de aceptación

1. Se instala sin dependencias externas.
2. Cien llamadas a `get()` generan un solo login y una sola lectura.
3. Si falta un puntero o una clave, el error la nombra y no muestra valores.
4. `fake()` funciona sin red ni punteros.
5. Los tests de `tests/test_client.py` pasan en CI.

---

## Código

### Estructura

```
vault-config/
├── pyproject.toml
├── README.md
├── src/vault_config/
│   ├── __init__.py
│   ├── _client.py
│   └── testing.py
└── tests/test_client.py
```

### `pyproject.toml`

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "tuorg-vault-config"
version = "0.1.0"
description = "Configuración desde Vault (auth Kubernetes + KV v2)"
requires-python = ">=3.10"
dependencies = []
```

### `src/vault_config/__init__.py`

```python
from ._client import VaultConfigError, get, get_bool, get_int, reload

__all__ = ["VaultConfigError", "get", "get_bool", "get_int", "reload"]
__version__ = "0.1.0"
```

### `src/vault_config/_client.py`

```python
"""Lectura de configuración desde Vault (auth Kubernetes + KV v2)."""
from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

TIMEOUT = 5.0
_DEFAULT_SA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount"
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}

_lock = threading.Lock()
_cache: dict[str, dict[str, Any]] = {}
_token: str | None = None
_override: dict[str, Any] | None = None


class VaultConfigError(RuntimeError):
    """Error de configuración. Nunca incluye tokens ni valores."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _pointer(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if not value:
        raise VaultConfigError(f"Falta el puntero {name}")
    return value


def _sa_file(name: str) -> str:
    path = Path(os.environ.get("VAULT_AUTH_TOKEN_PATH") or _DEFAULT_SA_PATH) / name
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        raise VaultConfigError(f"No se pudo leer {path}") from None


def _request(req: urllib.request.Request) -> Any:
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        raise VaultConfigError(f"Vault respondió HTTP {exc.code}", exc.code) from None
    except (urllib.error.URLError, TimeoutError) as exc:
        reason = getattr(exc, "reason", type(exc).__name__)
        raise VaultConfigError(f"No se pudo contactar a Vault: {reason}") from None


def _login(addr: str) -> str:
    body = _request(
        urllib.request.Request(
            f"{addr}/v1/auth/kubernetes/login",
            data=json.dumps(
                {"role": _pointer("VAULT_ROLE"), "jwt": _sa_file("token")}
            ).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
    )
    try:
        return body["auth"]["client_token"]
    except (KeyError, TypeError):
        raise VaultConfigError("Respuesta de login inválida") from None


def _fetch(secret_name: str) -> dict[str, Any]:
    global _token
    addr = _pointer("VAULT_ADDR").rstrip("/")
    mount = _pointer("VAULT_KV_MOUNT", "secret").strip("/")
    url = f"{addr}/v1/{mount}/data/{_sa_file('namespace')}/{secret_name}"

    for retry in (False, True):
        if _token is None:
            _token = _login(addr)
        try:
            body = _request(
                urllib.request.Request(url, headers={"X-Vault-Token": _token})
            )
            break
        except VaultConfigError as exc:
            if exc.status == 404:
                raise VaultConfigError(f"No existe el secreto {secret_name!r}") from None
            if exc.status != 403 or retry:
                raise
            _token = None  # token vencido o revocado: un reintento con login nuevo

    data = body.get("data", {}).get("data") if isinstance(body, dict) else None
    if not isinstance(data, dict):
        raise VaultConfigError(f"Respuesta inválida al leer {secret_name!r}")
    return data


def _secret(secret_name: str | None) -> dict[str, Any]:
    with _lock:
        if _override is not None:
            return _override
        name = (secret_name or _pointer("VAULT_SECRET_NAME")).strip("/")
        if name not in _cache:
            _cache[name] = _fetch(name)
        return _cache[name]


def get(key: str, secret_name: str | None = None) -> str:
    """Devuelve un campo del secreto. Sin secret_name usa VAULT_SECRET_NAME."""
    data = _secret(secret_name)
    if key not in data:
        raise VaultConfigError(f"Falta la clave {key!r} en el secreto")
    value = data[key]
    return value if isinstance(value, str) else str(value)


def get_bool(key: str, secret_name: str | None = None) -> bool:
    raw = get(key, secret_name).strip().lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    raise VaultConfigError(f"La clave {key!r} no es un booleano válido")


def get_int(key: str, secret_name: str | None = None) -> int:
    try:
        return int(get(key, secret_name).strip())
    except ValueError:
        raise VaultConfigError(f"La clave {key!r} no es un entero válido") from None


def reload() -> None:
    """Descarta la caché y el token; la próxima lectura vuelve a Vault."""
    global _token
    with _lock:
        _cache.clear()
        _token = None
```

### `src/vault_config/testing.py`

```python
"""Ayudas para pruebas. Solo se activan desde código, nunca por entorno."""
from contextlib import contextmanager
from typing import Any, Iterator, Mapping

from . import _client


@contextmanager
def fake(values: Mapping[str, Any]) -> Iterator[None]:
    """Reemplaza la lectura de Vault por un diccionario, sin red."""
    with _client._lock:
        previous = _client._override
        _client._override = dict(values)
    try:
        yield
    finally:
        with _client._lock:
            _client._override = previous
```

### `tests/test_client.py`

```python
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
```
