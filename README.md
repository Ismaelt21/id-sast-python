# id-sast-python

`id-sast-python` es el microservicio independiente de analisis estatico para
proyectos Python dentro de la arquitectura multilenguaje de `id-sast`.

Este componente se mantiene separado de `id-sast-csharp` para evitar un diseño
monolitico y permitir una evolucion independiente por lenguaje. Cada motor
conserva su propio repositorio, su propia API, su propia CLI, su propia capa de
persistencia y su propia configuracion de infraestructura.

## Proposito academico

Este repositorio implementa la parte correspondiente al analisis de seguridad
para Python. Su objetivo es identificar patrones de riesgo, construir evidencia
de analisis y generar reportes que puedan ser consumidos desde la API HTTP o
desde la linea de comandos.

En la tesis, este componente puede describirse como un servicio especializado
que:

- analiza codigo fuente Python de forma estatica;
- organiza el resultado por hallazgos, estadisticas y metadatos del escaneo;
- genera salidas en JSON, HTML y consola;
- opcionalmente persiste resultados en MongoDB con configuracion propia;
- expone la misma funcionalidad por API y por CLI;
- mantiene compatibilidad con Docker y con ejecucion local.

## Alcance tecnico

El servicio incluye las siguientes capas:

- `api/`: contrato HTTP con FastAPI.
- `cli/`: comandos locales para ejecucion manual y validacion rapida.
- `core/`: logica principal de analisis.
- `engine/`: orquestacion del motor `PySAST`.
- `service/`: caso de uso y coordinacion del escaneo.
- `database/`: persistencia separada para Python.
- `reports/`: generacion de salidas en JSON, HTML y consola.
- `samples/`: ejemplos vulnerables de referencia.
- `tests/`: pruebas unitarias, integracion y benchmarks.

## Contrato del servicio

### API HTTP

- `GET /health`
- `GET /version`
- `POST /scan`
- `GET /scan/{id}`

### CLI

El servicio puede ejecutarse de forma local mediante consola:

```powershell
id-sast-python health
id-sast-python version
id-sast-python scan .\samples\vulnerable\sqli --no-ai --json-only
```

Tambien puede ejecutarse sin instalarlo globalmente:

```powershell
python -m cli.main health
python -m cli.main scan .\samples\vulnerable\sqli --no-ai --json-only
```

## Requisitos recomendados

Para una ejecucion reproducible se recomienda:

- Python 3.11 o superior.
- `venv` para aislar dependencias.
- Docker, si se desea validar el contenedor.
- MongoDB, si se activa la persistencia.

## Instalacion

La forma recomendada de instalacion es a traves de `pyproject.toml`.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

Con esto quedan disponibles los entrypoints:

```powershell
id-sast-python
id-sast-python-api
```

Si tambien deseas ejecutar pruebas locales:

```powershell
python -m pip install pytest
```

### Nota sobre `requirements.txt`

El archivo `requirements.txt` se conserva como referencia de compatibilidad,
pero la ruta principal del proyecto es `pyproject.toml`.

## Configuracion

La configuracion se toma desde variables de entorno. El archivo de ejemplo es
`.env.example`.

### Variables principales

```env
APP_NAME=id-sast-python
ENVIRONMENT=development
DEBUG=false

USE_GEMINI=true
ENABLE_AI_ANALYSIS=true
GOOGLE_GEMINI_API_KEY=
GEMINI_MODEL=gemini-1.5-pro

USE_PERSISTENCE=true
MONGODB_URI=mongodb+srv://user:password@cluster.mongodb.net/?retryWrites=true&w=majority
MONGODB_DB_NAME=id_sast_python
MONGODB_RULES_COLLECTION=security_rules
MONGODB_ANALYSIS_COLLECTION=analyses
MONGODB_SCANS_COLLECTION=scans

REPORTS_DIR=reports/output
STORAGE_DIR=storage
RULE_CACHE_DIR=storage/rules
TEMP_DIR=storage/temp
```

### Observaciones de arquitectura

- La base de datos de Python debe ser independiente de la de C#.
- La persistencia de cada microservicio debe configurarse por separado.
- Si `USE_PERSISTENCE=false`, el motor puede ejecutarse sin escribir en MongoDB.
- Si `USE_GEMINI=false` o `ENABLE_AI_ANALYSIS=false`, el analisis se ejecuta sin
  asistencia de IA.
- `config/settings.py` es la fuente de verdad para cargar la configuracion.

## Ejecucion local

### CLI

```powershell
id-sast-python scan .\samples\vulnerable\unsafe_eval --no-persist --html-only
id-sast-python scan .\samples\vulnerable\sqli --no-ai --json-only
id-sast-python scan .\samples\vulnerable\xss --no-persist --html-only
```

### Comportamiento de la salida

La CLI imprime en consola un documento JSON con el resultado del escaneo,
incluso cuando se usan banderas como `--html-only` o `--json-only`. Los
artefactos generados se escriben por separado en `reports/output/`.

Si el campo `reports.html` o `reports.json` aparece como `null`, significa que
la generacion del archivo correspondiente fallo durante el proceso de exportacion.

### API

```powershell
id-sast-python-api
```

La API queda disponible en `http://127.0.0.1:8000`.

## Persistencia

Cuando la persistencia esta habilitada, el servicio guarda informacion del
escaneo en la coleccion correspondiente de MongoDB.

Se utilizan colecciones separadas para:

- escaneos;
- analisis;
- reglas de seguridad.

Esto permite mantener el aislamiento por microservicio y evitar una base
compartida entre motores de distinto lenguaje.

## Docker

El proyecto incluye soporte para contenedorizacion:

```powershell
docker compose up --build
```

El contenedor arranca la API usando el entrypoint `id-sast-python-api`
definido en `pyproject.toml`.

Para ejecutar la CLI dentro del contenedor:

```powershell
docker compose run --rm id-sast-python id-sast-python scan .\samples\vulnerable\sqli --no-ai --json-only
```

## Reportes generados

El motor puede producir salidas en:

- JSON para integracion con otras capas;
- HTML para visualizacion humana;
- consola para ejecucion rapida.

Los reportes HTML se generan en `reports/output/` y buscan mantener una
narrativa visual consistente con el componente C#.

El reporte incluye hallazgos, severidad, confianza, CWE, linea, ruta de taint,
resumen estadistico y contexto de remediacion.

## Benchmarks de tesis

El repositorio incluye dos conjuntos de benchmarks para validacion:

- `tests/samples/thesis_case/`: benchmark principal positivo.
- `tests/samples/thesis_case_controls/`: controles negativos con pares
  vulnerable/seguro y helpers inocuos.

Para ejecutar el benchmark desde la CLI del producto:

```powershell
id-sast-python scan .\tests\samples\thesis_case\ --no-persist --html-only
id-sast-python scan .\tests\samples\thesis_case_controls\ --no-persist --html-only
```

Para ejecutar la validacion dedicada del corpus de tesis:

```powershell
python .\tests\run_thesis_benchmarks.py
python -m pytest .\tests\test_thesis_benchmarks.py
```

Actualmente el corpus cubre estas categorias en el benchmark principal:

- `SQL_INJECTION`
- `PATH_TRAVERSAL`
- `SSRF`
- `XSS`
- `OPEN_REDIRECT`
- `XXE`

En el estado actual del motor, `OPEN_REDIRECT` y `XXE` se mantienen como gaps
conocidos del pipeline, documentados en las pruebas para no ocultar limitaciones
reales del analizador.

## Validacion general

Para comprobar el funcionamiento del servicio:

```powershell
python -m pytest
id-sast-python scan .\samples\vulnerable\unsafe_eval --no-persist --html-only
id-sast-python scan .\samples\vulnerable\hardcoded_secrets --no-persist --html-only
id-sast-python scan .\samples\vulnerable\xss --no-persist --html-only
```

## Estado del componente

El motor principal de analisis vive en `engine/pysast.py`. El archivo `main.py`
se conserva como wrapper de compatibilidad para no romper escenarios previos,
mientras que la ejecucion oficial del servicio se centraliza en los entrypoints
del paquete.

## Observaciones de implementacion

- `main.py` ya no es el punto principal de ejecucion; funciona como wrapper de
  compatibilidad.
- El escaneo de cada lenguaje debe mantenerse aislado en su propio repositorio,
  base de datos y configuracion de despliegue.
- La CLI, la API y los reportes comparten el mismo pipeline de analisis.
