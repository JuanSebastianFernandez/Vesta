# VESTA Backend

Backend API para análisis de código del módulo de prevención de VESTA.

## Requisitos
- Python 3.12
- PostgreSQL 14+ (base `vesta_db`)
- Extensión `pgvector` habilitada en la base

## Quickstart
1. Crear y activar entorno virtual:
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

2. Instalar dependencias:
```powershell
pip install -r requirements.txt
```

3. Configurar variables de entorno:
```powershell
Copy-Item .env.example .env
```

4. Preparar PostgreSQL:
- Crear base de datos `vesta_db`.
- Crear/usar rol según `.env`.
- Ejecutar en la DB:
```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

5. Ejecutar API:
```powershell
uvicorn app.main:app --reload
```

6. Verificar:
- Health: `GET http://127.0.0.1:8000/health/`
- Docs: `http://127.0.0.1:8000/docs`

## Variables de entorno
- `GITHUB_WEBHOOK_SECRET`: secreto para validar webhook de GitHub.
- `GITLAB_WEBHOOK_SECRET`: secreto para webhook de GitLab.
- `AVAILABLE_SERVER`: `false` usa credenciales locales, `true` usa `SERVER_WEB`.
- `ROLE_NAME_POSTGRESQL`: rol local de PostgreSQL.
- `PASSWORD_POSTGRESQL`: password del rol local.
- `SERVER_WEB`: URL completa de conexión PostgreSQL cuando `AVAILABLE_SERVER=true`.
- `PREDICTION_THRESHOLD_SUSPICIOUS`: umbral inferior para zona gris (`SUSPICIOUS`).
- `PREDICTION_THRESHOLD_MALICIOUS`: umbral superior para marcar `MALICIOUS`.
- `DAST_ENABLED`: activa/desactiva análisis dinámico en Docker.
- `DAST_DOCKER_IMAGE`: imagen usada para sandbox DAST.
- `DAST_TIMEOUT_SECONDS`: timeout máximo del contenedor DAST.
- `DAST_MEMORY_LIMIT`: límite de memoria del contenedor (ej. `256m`).
- `DAST_PIDS_LIMIT`: límite de procesos del contenedor.
- `DAST_CPU_QUOTA`: cuota de CPU del contenedor (sobre periodo 100000).
- `DAST_NETWORK_MODE`: modo de red de Docker para DAST (`none`, `bridge`, etc.).
- `DAST_TSHARK_ENABLED`: activa captura de tráfico de red con `tshark`.
- `DAST_TSHARK_PATH`: binario/ruta de `tshark`.
- `DAST_TSHARK_INTERFACE`: interfaz a capturar (ej. `any`).

## Calibración de umbral (Issue 6.1)
Para evitar el sesgo de “todo malicioso”, calibra el umbral con datos reales de tu entorno.

Formato CSV esperado:
- columna `y_true` con etiqueta real (`0` benigno, `1` malicioso)
- columna `y_prob` con probabilidad predicha por el modelo

Ejemplo de ejecución:
```powershell
python scripts/calibrate_threshold.py --input-csv data\predictions.csv --output-json calibration.json
```

El script imprime:
- `best_threshold_malicious`
- `recommended_threshold_suspicious`
- matriz de confusión y métricas (precision/recall/F1/AUC)

## Decisión híbrida ML + ANTLR
La clasificación final no depende solo del modelo:
- si ANTLR muestra señal muy baja en código grande, puede bajar un falso positivo de `MALICIOUS` a `BENIGN`.
- si ANTLR muestra señal muy alta en código corto/denso, puede subir un falso negativo de `BENIGN` a `SUSPICIOUS`.

Script para simular la decisión híbrida sobre reportes:
```powershell
python scripts/antlr_hybrid_decision.py --input-json data\reports.json --output-json data\hybrid_results.json
```

Formato esperado por entrada JSON:
- `model_prediction_binary` (0/1)
- `model_prediction_probability` (0-1)
- `original_code`
- `static_findings` (array ANTLR con `weight` y/o `severity`)

## Notas
- Los modelos ML deben estar disponibles en `ml_models/`.
- Los repositorios clonados se almacenan en `~/vesta_cloned_repos`.
- DAST se ejecuta en contenedor restringido (`cap_drop=ALL`, `no-new-privileges`) y el modo de red se controla con `DAST_NETWORK_MODE`.
- Para captura de red, `tshark` debe estar instalado en el host (en Windows normalmente con Npcap) y con permisos para capturar en la interfaz configurada.
