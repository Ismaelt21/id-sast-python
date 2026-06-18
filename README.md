# id-sast-python

Microservicio independiente de analisis estatico para Python.

Este repo se separa de `id-sast-csharp` para mantener una arquitectura por lenguaje:

- un repo por lenguaje
- una API HTTP por servicio
- una CLI local por servicio
- un `core` compartido dentro del propio servicio
- persistencia aislada por microservicio y por base de datos

## Estructura propuesta

- `api/`: capa HTTP con FastAPI
- `cli/`: comandos locales
- `core/`: motor de analisis Python ya existente
- `service/`: orquestacion del scan y contrato de aplicacion
- `database/`: MongoDB y repositorios
- `reports/`: generacion de salidas
- `samples/`: casos de prueba para el motor
- `tests/`: pruebas unitarias e integracion

## Contrato HTTP

- `GET /health`
- `GET /version`
- `POST /scan`
- `GET /scan/{id}`

### `POST /scan`

```json
{
  "project_path": "C:\\ruta\\al\\proyecto",
  "use_ai": true,
  "persist": true,
  "json_only": false,
  "html_only": false,
  "verbose": false
}
```

## CLI

```powershell
python -m cli.main scan .\\samples\\vulnerable\\sqli --no-ai --json-only
python -m cli.main health
python -m cli.main version
```

If you install the package, the entrypoints are:

```powershell
id-sast-python scan .\\samples\\vulnerable\\sqli --no-ai --json-only
id-sast-python-api
```

## Configuracion de persistencia

Usa una base de datos separada para Python:

- `MONGODB_DB_NAME=id_sast_python`
- `MONGODB_SCANS_COLLECTION=scans`
- `MONGODB_ANALYSIS_COLLECTION=analyses`
- `MONGODB_RULES_COLLECTION=security_rules`

## Docker

```powershell
docker compose up --build
```

The container starts the API through the `id-sast-python-api` entrypoint defined in `pyproject.toml`. If you want to run the CLI inside the container, override the command, for example:

```powershell
docker compose run --rm id-sast-python id-sast-python scan .\samples\vulnerable\sqli --no-ai --json-only
```

## Estado actual

El motor de analisis existente ahora vive en `engine/pysast.py` y `main.py` quedó como wrapper de compatibilidad. Eso permite avanzar rapido sin perder el pipeline actual.
