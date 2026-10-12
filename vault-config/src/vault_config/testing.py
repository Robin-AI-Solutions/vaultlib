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
