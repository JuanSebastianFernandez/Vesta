# Documentación de Salida de Análisis (`/prevention/jobs/{job_id}/result`)

Este documento describe el contrato JSON de salida para resultados de análisis asíncronos del módulo de prevención.

## 1) Estructura general

```json
{
  "job_id": "uuid",
  "status": "DONE|FAILED|RUNNING|PENDING",
  "result": {
    "schema_version": "1.0.0",
    "repository": { ... },
    "analysis": { ... },
    "summary": { ... },
    "totals": { ... },
    "risk": { ... },
    "dast": { ... },
    "files": [ ... ],
    "reports": [ ... ]
  }
}
```

## 2) Campos de nivel superior

| Campo | Tipo | Descripción |
|---|---|---|
| `job_id` | `string` | ID único del trabajo asíncrono. |
| `status` | `string` | Estado actual del job (`PENDING`, `RUNNING`, `DONE`, `FAILED`). |
| `result` | `object` | Resultado completo del análisis (contrato versionado). |

## 3) `result.schema_version`

| Campo | Tipo | Descripción |
|---|---|---|
| `schema_version` | `string` | Versión del contrato JSON de salida (actual: `1.0.0`). |

## 4) `result.repository`

| Campo | Tipo | Descripción |
|---|---|---|
| `id` | `number \| null` | ID interno de la tabla `repository`. |
| `url` | `string` | URL del repositorio analizado. |
| `name` | `string` | Nombre normalizado del repositorio. |
| `commit_hash` | `string \| null` | Commit/branch usado para ejecutar el análisis. |

## 5) `result.analysis`

| Campo | Tipo | Descripción |
|---|---|---|
| `job_id` | `string` | ID del job dentro del contrato. |
| `status` | `string` | Estado final del job. |
| `trigger_source` | `string` | Origen del análisis (`MANUAL`, `WEBHOOK_GITHUB`, etc.). |
| `created_at` | `string \| null` | Fecha de creación del job (UTC ISO8601). |
| `started_at` | `string \| null` | Fecha de inicio real de ejecución (UTC ISO8601). |
| `finished_at` | `string \| null` | Fecha de finalización (UTC ISO8601). |
| `duration_seconds` | `number \| null` | Duración total del job en segundos. |

## 6) `result.summary`

| Campo | Tipo | Descripción |
|---|---|---|
| `total_reports` | `number` | Total de archivos reportados. |
| `status_counts` | `object` | Conteo agregado por estado de seguridad. |

Estados posibles en `status_counts`:
- `BENIGN`
- `SUSPICIOUS`
- `MALICIOUS`
- `SKIPPED`
- `ANALYSIS_ERROR`
- `POTENTIALLY_MALFORMED`
- `UNKNOWN`

## 7) `result.totals`

| Campo | Tipo | Descripción |
|---|---|---|
| `files_analyzed` | `number` | Número de archivos incluidos en `files`. |
| `files_with_findings` | `number` | Número de archivos con hallazgos (`amount_findings > 0`). |
| `findings_total` | `number` | Suma total de hallazgos de todos los archivos. |

## 8) `result.risk` (score unificado SAST + DAST)

| Campo | Tipo | Descripción |
|---|---|---|
| `risk_score` | `number` | Score final unificado (0 a 100). |
| `risk_level` | `string` | Nivel del score (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |
| `formula_version` | `string` | Versión de la fórmula (actual: `v1.0.0`). |
| `weights` | `object` | Pesos usados para combinar componentes (`sast`, `dast`). |
| `components` | `object` | Componentes y aportes ponderados (`sast_score`, `dast_score`, etc.). |
| `thresholds` | `object` | Rango numérico por nivel (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |
| `details` | `object` | Desglose técnico de cálculo SAST y DAST. |

### Fórmula actual

```text
risk_score = (sast_score * 0.60) + (dast_score * 0.40)
```

## 9) `result.dast` (análisis dinámico)

| Campo | Tipo | Descripción |
|---|---|---|
| `engine` | `string` | Motor de ejecución dinámica (ej. `docker`). |
| `status` | `string` | Estado del DAST (`SUCCESS`, `FAILED`, `DISABLED`, etc.). |
| `message` | `string` | Mensaje de resultado operativo del DAST. |
| `metrics` | `object` | Métricas del probe dinámico (conteos por tipo de archivo, etc.). |
| `cap_drop` | `array` | Capacidades Linux removidas del contenedor. |
| `security_opt` | `array` | Opciones de seguridad del contenedor. |
| `cpu_quota` | `number` | Cuota de CPU del contenedor. |
| `memory_limit` | `string` | Límite de memoria del contenedor. |
| `pids_limit` | `number` | Límite de procesos del contenedor. |
| `network_mode` | `string` | Modo de red (`none`, `bridge`, etc.). |
| `container_image` | `string` | Imagen Docker usada. |
| `repo_path` | `string` | Ruta local del repo clonado para análisis. |
| `started_at` | `string` | Inicio del DAST (UTC ISO8601). |
| `finished_at` | `string` | Fin del DAST (UTC ISO8601). |
| `duration_seconds` | `number` | Duración del DAST en segundos. |
| `container_exit_code` | `number \| null` | Código de salida del contenedor. |
| `logs_excerpt` | `string` | Extracto de logs del probe. |
| `network_capture` | `object` | Resultado de captura de red (tshark). |

### `dast.network_capture`

| Campo | Tipo | Descripción |
|---|---|---|
| `status` | `string` | Estado de la captura (`PARSED`, `NO_CAPTURE_OUTPUT`, `DISABLED`, etc.). |
| `metrics` | `object` | Indicadores de red (paquetes, DNS, puertos, SYN, destinos). |
| `pcap_path` | `string` | Ruta temporal del pcap (vacía tras limpieza). |

## 10) `result.files` (canónico por archivo)

Cada elemento representa un archivo del repositorio.

| Campo | Tipo | Descripción |
|---|---|---|
| `file_hash` | `string \| null` | Hash único del archivo en contexto repo+commit+ruta+contenido. |
| `file_name` | `string \| null` | Nombre del archivo. |
| `language` | `string \| null` | Lenguaje detectado. |
| `security_status` | `string \| null` | Clasificación final (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`, etc.). |
| `label` | `number \| null` | Etiqueta binaria final (0/1) cuando aplica. |
| `prediction_probability` | `number \| null` | Probabilidad reportada por el pipeline ML. |
| `risk_score` | `number \| null` | Score de riesgo por archivo (0 a 100). |
| `amount_findings` | `number` | Número de hallazgos ANTLR del archivo. |
| `findings_total` | `number` | Alias agregado de hallazgos por archivo. |
| `has_findings` | `boolean` | `true` si `amount_findings > 0`. |
| `prediction_source` | `string \| null` | Fuente de predicción (ej. `ML_ANTLR_HYBRID`). |
| `message` | `string \| null` | Mensaje de interpretación del resultado de archivo. |

## 11) `result.reports` (compatibilidad)

- `reports` contiene el mismo contenido que `files`.
- Se mantiene para compatibilidad con consumidores anteriores.
- Para nuevas integraciones, usar `files` como arreglo canónico.

## 12) Interpretación práctica de estados relevantes

- `POTENTIALLY_MALFORMED`: ANTLR detectó errores de parsing/sintaxis; requiere revisión manual.
- `SUSPICIOUS`: archivo en zona gris; revisar hallazgos y contexto.
- `MALICIOUS`: archivo con alta evidencia de comportamiento malicioso.
- `NO_CAPTURE_OUTPUT` en DAST: el DAST corrió, pero no hubo evidencia de red parseable durante la ventana de captura.

