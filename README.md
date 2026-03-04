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
- `DEFENSE_AUTO_CLOSE_STALE_ALERTS`: activa autocierre TTL de alertas `OPEN` en módulo defensa.
- `DEFENSE_ALERT_TTL_MINUTES`: minutos de inactividad para autocierre.
- `DEFENSE_AUTO_CLOSE_INCLUDE_CRITICAL`: incluye `CRITICAL` en autocierre TTL.
- `DEFENSE_GRPC_ENABLED`: activa trigger gRPC hacia contención/honeypot.
- `DEFENSE_GRPC_TARGET`: host:puerto del orquestador gRPC de contención.
- `DEFENSE_GRPC_TIMEOUT_SECONDS`: timeout por intento gRPC.
- `DEFENSE_GRPC_RETRY_MAX`: reintentos máximos por trigger.
- `DEFENSE_GRPC_RETRY_BACKOFF_SECONDS`: backoff lineal entre reintentos.
- `DEFENSE_GRPC_TRIGGER_MIN_SCORE`: score mínimo para disparar trigger.

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

## Score de Riesgo Unificado (Issue 13)
El resultado final del job asíncrono incluye `result.unified_risk` con una fórmula única de 0 a 100.

Fórmula versionada (`v1.0.0`):
- `unified_risk_score = sast_score * 0.60 + dast_score * 0.40`

Niveles:
- `LOW`: 0.00 - 24.99
- `MEDIUM`: 25.00 - 49.99
- `HIGH`: 50.00 - 74.99
- `CRITICAL`: 75.00 - 100.00

Dónde aparece:
- `GET /prevention/jobs/{job_id}/result` -> `result.unified_risk`

Contenido principal:
- `risk_score`, `risk_level`
- `formula_version`, `weights`, `thresholds`
- `components` (`sast_score`, `dast_score`, ponderados)
- `details` con desglose de señales SAST y DAST usadas

## Contrato JSON Dashboard (Issue 14)
El endpoint `GET /prevention/jobs/{job_id}/result` retorna un contrato estable y versionado en `result`.

Campos top-level del contrato:
- `schema_version`
- `repository`
- `analysis`
- `summary`
- `totals`
- `risk`
- `dast`
- `files` (canónico por archivo)
- `reports` (alias de compatibilidad, mismo contenido que `files`)

Ejemplo resumido:
```json
{
  "schema_version": "1.0.0",
  "repository": {"id": 6, "url": "https://github.com/org/repo", "name": "repo", "commit_hash": "main"},
  "analysis": {"job_id": "uuid", "trigger_source": "MANUAL", "status": "DONE"},
  "summary": {"total_reports": 7, "status_counts": {"BENIGN": 2, "SUSPICIOUS": 3, "SKIPPED": 2}},
  "totals": {"files_analyzed": 7, "files_with_findings": 3, "findings_total": 5},
  "risk": {"risk_score": 52.4, "risk_level": "HIGH", "formula_version": "v1.0.0"},
  "dast": {"status": "SUCCESS"},
  "files": [{"file_name": "main.py", "security_status": "SUSPICIOUS", "amount_findings": 2}],
  "reports": [{"file_name": "main.py", "security_status": "SUSPICIOUS", "amount_findings": 2}]
}
```

## Histórico y Validación ANTLR (Issue 15)
Se agregaron endpoints para consultar histórico por repositorio y validar la consistencia de `antlr_report`.

### 1) Histórico paginado por repositorio
`GET /prevention/reports/{repository_id}`

Query params:
- `page` (default `1`)
- `page_size` (default `20`, max `200`)
- `language` (opcional)
- `security_status` (opcional: `BENIGN|SUSPICIOUS|MALICIOUS|UNKNOWN`)
- `include_antlr_report` (`true|false`)
- `include_antlr_features` (`true|false`)
- `include_antlr_validation` (`true|false`)
- `include_source_code` (`true|false`)

### 2) Validación ANTLR por repositorio
`GET /prevention/reports/{repository_id}/antlr-validation`

Retorna:
- resumen global (`valid_reports`, `invalid_reports`)
- detalle por archivo
- validación por componente/hallazgo (`components`) con `issues` por finding

## Defensa Activa por Telemetría de Logs (Issue 16)
Se agregó un router independiente en `"/defense"` para análisis conductual sobre eventos de logs/red y persistencia de patrones/alertas en BD.

Tablas nuevas:
- `defense_log_event`: eventos ingeridos con contexto y payload crudo.
- `threat_pattern_rule`: reglas de comportamiento persistidas/ajustables.
- `threat_alert`: alertas generadas con severidad, score, confianza y evidencia contextual.

Endpoints principales:
- `POST /defense/events`: ingesta 1 evento y evaluación contextual.
- `POST /defense/events/batch`: ingesta por lote.
- `POST /defense/events/reanalyze`: recalcula alertas históricas tras ajuste de reglas.
- `GET /defense/events`: consulta eventos con filtros y paginación.
- `POST /defense/rules/seed`: siembra/sincroniza reglas por defecto.
- `GET /defense/rules`: lista reglas activas.
- `PATCH /defense/rules/{rule_id}`: ajusta umbrales/ventanas/pesos/severidad.
- `GET /defense/alerts`: lista alertas con filtros y paginación.
- `GET /defense/alerts/{alert_id}`: detalle de alerta.
- `PATCH /defense/alerts/{alert_id}/status`: transición `OPEN|ACKNOWLEDGED|RESOLVED`.
- `POST /defense/alerts/auto-close`: cierre automático manual por TTL.

Reglas iniciales (MVP):
- `BRUTE_FORCE_AUTH`
- `LATERAL_MOVEMENT_SCAN`
- `SUSPICIOUS_COMMAND_EXECUTION`
- `DATA_EXFILTRATION_PATTERN`
- `RANSOMWARE_BEHAVIORAL_PATTERN`

Ejemplo de ingesta:
```json
{
  "repository_id": 7,
  "source_system": "EDR",
  "source_ip": "10.20.30.40",
  "host_id": "ws-001",
  "user_id": "alice",
  "event_type": "COMMAND_EXECUTION",
  "severity": "HIGH",
  "message": "PowerShell encoded command detected",
  "event_time": "2026-03-01T10:20:30Z",
  "event_context": {
    "suspicious_command": true,
    "process_name": "powershell.exe",
    "destination_ip": "185.10.10.10",
    "bytes_out": 1200000
  },
  "raw_payload": {"vendor": "edr-x", "event_id": "evt-123"}
}
```

Mejoras Issue 16.1:
- Deduplicación por `raw_payload.event_id` (o `event_external_id`) para ignorar eventos repetidos SIEM/EDR.
- Reanálisis histórico por ventana/repositorio/fuente para recalcular alertas luego de cambios en reglas.
- Cierre automático de alertas `OPEN` inactivas (TTL configurable) para reducir fatiga operativa.

## Trigger gRPC a Contención/Honeypot (Issue 17)
Se agregó integración gRPC stub para notificar al módulo de contención cuando la amenaza supera umbral operativo.

Objetivo:
- desacoplar detección (defense) de respuesta (containment/honeypot),
- disparar respuesta solo bajo condiciones fuertes,
- no bloquear análisis si el destino gRPC falla.

Archivo proto mínimo:
- `app/grpc/protos/containment_trigger.proto`
- servicio: `vesta.containment.ContainmentOrchestrator/TriggerContainment`
- mensajes: `ContainmentRequest`, `ContainmentResponse`.

Cliente stub:
- `app/services/containment_grpc_client.py`
- conexión `grpc.insecure_channel(...)`
- llamada unary `TriggerContainment`
- reintentos con backoff y timeout configurable.

Regla de disparo automático:
- se evalúa en `NetworkAnalyzerService` después de generar alertas por evento.
- solo dispara si:
  - `action_recommended` es `ESCALATE_SOC` o `TRIGGER_CONTAINMENT`,
  - `max_alert_score >= DEFENSE_GRPC_TRIGGER_MIN_SCORE`.
- si no cumple, retorna `containment_trigger.status = SKIPPED`.

Resiliencia:
- si falla gRPC, no se cae el flujo de análisis del evento.
- el resultado queda en `containment_trigger` con `status = FAILED`.
- se registran intentos y error en logs.

Dónde se ve el resultado:
- `POST /defense/events` -> campo `containment_trigger` en la respuesta.
- `POST /defense/events/batch` -> agrega `containment_triggers_sent`.

Endpoint de prueba manual:
- `POST /defense/containment/trigger-test`
- envía payload arbitrario al stub para validar conectividad/reintentos sin esperar detección real.

Pruebas automáticas asociadas:
- `test/test_containment_grpc_client.py` (skip, retry-success, retry-failed).
- `test/test_network_analyzer_service.py` (disparo condicional por umbral).

## Módulo de Contención (Issue 18)
Se agregó el router `/containment` con acciones stub auditadas:
- `POST /containment/isolate-node`
- `POST /containment/block-ip`
- `POST /containment/restore-backup`
- `POST /containment/deploy-honeypot`
- `GET /containment/actions`
- `GET /containment/actions/{action_id}`
- `PATCH /containment/actions/{action_id}/status`

Toda acción se persiste en `containment_action_audit` con `who/when/why`, estado y detalles.

Documentación operativa completa:
- `defense_containment_honeypot_operations.md`

## Notas
- Los modelos ML deben estar disponibles en `ml_models/`.
- Los repositorios clonados se almacenan en `~/vesta_cloned_repos`.
- DAST se ejecuta en contenedor restringido (`cap_drop=ALL`, `no-new-privileges`) y el modo de red se controla con `DAST_NETWORK_MODE`.
- Para captura de red, `tshark` debe estar instalado en el host (en Windows normalmente con Npcap) y con permisos para capturar en la interfaz configurada.
