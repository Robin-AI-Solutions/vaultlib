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
