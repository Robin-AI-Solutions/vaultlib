# vault-config

Librería Python para leer configuración desde Vault (auth Kubernetes + KV v2). Las aplicaciones importan esta librería y no leen `VAULT_*` ni usan `os.environ` en su propio código.

Solo biblioteca estándar. Python 3.10+.

## Instalación

El paquete se publica como `robin-ai-solutions-vault-config` desde [Robin-AI-Solutions/vaultlib](https://github.com/Robin-AI-Solutions/vaultlib), en el subdirectorio `vault-config`. Fija el tag:

```
pip install "git+https://github.com/Robin-AI-Solutions/vaultlib@v0.1.0#subdirectory=vault-config"
```

En `requirements.txt`:

```
robin-ai-solutions-vault-config @ git+https://github.com/Robin-AI-Solutions/vaultlib@v0.1.0#subdirectory=vault-config
```

## Uso

```python
from vault_config import get, get_bool, get_int

DB_HOST = get("DB_HOST")
DEBUG = get_bool("DEBUG")
PORT = get_int("PORT")
OTRO = get("API_KEY", secret_name="otro-secreto")
```

- `get(key, secret_name=None)` devuelve el campo como texto. Sin `secret_name` usa `VAULT_SECRET_NAME`.
- `get_bool` y `get_int` convierten el valor. El texto `"false"` es verdadero en Python, por eso existe `get_bool`.
- `reload()` descarta la caché y el token; la próxima lectura vuelve a Vault.

Si falta un puntero o una clave, se lanza `VaultConfigError`. El mensaje nombra lo que falta y no incluye valores ni el token.

## Punteros

Únicas variables de entorno que lee la librería:

| Variable | Obligatoria | Por defecto |
|----------|-------------|-------------|
| `VAULT_ADDR` | Sí | — |
| `VAULT_ROLE` | No | `vault-reader` |
| `VAULT_SECRET_NAME` | Sí, salvo que se pase `secret_name` | — |
| `VAULT_KV_MOUNT` | No | `secret` |
| `VAULT_AUTH_TOKEN_PATH` | No | `/var/run/secrets/kubernetes.io/serviceaccount` |

La librería hace login con el JWT del service account y lee KV v2 en `{mount}/data/{namespace}/{secret_name}`. Hay un login y una lectura por secreto durante la vida del proceso. Si Vault responde 403, hace login de nuevo y reintenta una vez. Cada llamada tiene un timeout de 5 segundos. No hay valores por defecto de configuración ni respaldo a otras variables de entorno.

## Pruebas

`fake()` sustituye Vault por un diccionario, sin red. Solo se activa desde código:

```python
from vault_config.testing import fake

with fake({"DB_HOST": "localhost", "DEBUG": "false"}):
    ...
```

Para ejecutar la suite:

```
pip install -e ".[test]"
pytest
```
