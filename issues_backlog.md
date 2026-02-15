# Backlog de Issues - VESTA Backend

## Issue 1: Corregir endpoint `/analayze-repository` y mantener compatibilidad
- **Tipo:** feat
- **Prioridad:** alta
- **Labels sugeridas:** `api`, `breaking-change`, `backward-compatible`, `P0`
- **Descripción:** Renombrar el endpoint a `/prevention/analyze-repository` y mantener temporalmente el endpoint legado para no romper clientes existentes.
- **Tareas:**
1. Crear nueva ruta `POST /prevention/analyze-repository`.
2. Mantener alias en `/prevention/analayze-repository` marcado como deprecado.
3. Actualizar docs OpenAPI y ejemplos.
- **Criterios de aceptación:**
1. Ambos endpoints funcionan y devuelven el mismo resultado.
2. OpenAPI marca el endpoint antiguo como deprecado.
3. Se registra warning cuando se usa el endpoint viejo.
- **Dependencias:** Ninguna
- **Estimación:** 0.5 día

## Issue 2: Completar `requirements.txt` con dependencias reales
- **Tipo:** chore
- **Prioridad:** alta
- **Labels sugeridas:** `dependencies`, `setup`, `P0`
- **Descripción:** Reflejar todas las librerías realmente usadas por el proyecto y fijar versiones críticas.
- **Tareas:**
1. Listar imports reales del código.
2. Añadir librerías faltantes.
3. Fijar `scikit-learn==1.4.*` por compatibilidad de modelos.
4. Verificar instalación en entorno limpio.
- **Criterios de aceptación:**
1. `pip install -r requirements.txt` completa sin errores.
2. App inicia correctamente tras instalación limpia.
3. Dependencias críticas quedan versionadas.
- **Dependencias:** Ninguna
- **Estimación:** 1 día

## Issue 3: Crear `.env.example` y documentación de arranque
- **Tipo:** docs
- **Prioridad:** media
- **Labels sugeridas:** `docs`, `setup`, `P1`
- **Descripción:** Documentar variables de entorno y pasos mínimos para correr backend + DB.
- **Tareas:**
1. Crear `.env.example` con todas las variables usadas por `Settings`.
2. Añadir sección "Quickstart" en README.
3. Documentar prerequisitos (PostgreSQL, pgvector, modelos).
- **Criterios de aceptación:**
1. Un desarrollador nuevo puede levantar API siguiendo solo README.
2. Variables obligatorias y opcionales están claras.
- **Dependencias:** Issue 2
- **Estimación:** 0.5 día

## Issue 4: Implementar extractor unificado de 12 features
- **Tipo:** feat
- **Prioridad:** alta
- **Labels sugeridas:** `ml`, `sast`, `feature-engineering`, `P0`
- **Descripción:** Implementar `feature_extractor` que produzca 12 features estables por archivo alineadas a requisitos.
- **Tareas:**
1. Crear `app/services/feature_extractor.py`.
2. Definir contrato de entrada/salida del vector.
3. Añadir validaciones y defaults seguros.
4. Cubrir casos de archivos vacíos o no parseables.
- **Criterios de aceptación:**
1. Todo reporte `SUCCESS` contiene 12 features numéricas válidas.
2. Se mantiene orden consistente de features.
3. Pruebas unitarias para extractor pasan.
- **Dependencias:** Issue 2
- **Estimación:** 2 días

## Issue 5: Integrar `feature_vector` en pipeline ANTLR/reportes
- **Tipo:** feat
- **Prioridad:** alta
- **Labels sugeridas:** `sast`, `antlr`, `pipeline`, `P0`
- **Descripción:** Integrar cálculo del vector en flujo de análisis para persistencia y predicción.
- **Tareas:**
1. Inyectar extractor al finalizar análisis por archivo.
2. Incluir `feature_vector` en `raw_report`.
3. Propagar al `ReportService`.
- **Criterios de aceptación:**
1. `raw_report` incluye siempre `feature_vector` para archivos compatibles.
2. No rompe reportes de `UNSUPPORTED_LANGUAGE` ni `PARSING_ERRORS`.
- **Dependencias:** Issue 4
- **Estimación:** 1 día

## Issue 6: Integrar predicción del metamodelo en `ReportService`
- **Tipo:** feat
- **Prioridad:** crítica
- **Labels sugeridas:** `ml`, `prediction`, `P0`
- **Descripción:** Activar uso real de `predict_malware_risk` en flujo principal.
- **Tareas:**
1. Descomentar/importar `predict_malware_risk`.
2. Consumir `feature_vector` por archivo.
3. Reemplazar asignación hardcode de `label`.
4. Manejar errores de modelo sin tumbar todo el lote.
- **Criterios de aceptación:**
1. `label` ya no depende de `benign=True` por defecto.
2. Se guarda probabilidad y clasificación.
3. Errores de predicción quedan trazables en logs/reportes.
- **Dependencias:** Issue 5
- **Estimación:** 1.5 días

## Issue 7: Extender modelo de datos para score/probabilidad
- **Tipo:** feat
- **Prioridad:** alta
- **Labels sugeridas:** `database`, `models`, `P0`
- **Descripción:** Añadir campos persistentes para salida de ML y score de riesgo.
- **Tareas:**
1. Agregar campos a `Report` (`prediction_probability`, `risk_score`, opcional `prediction_source`).
2. Ajustar modelos read/create.
3. Crear migración SQL (o script controlado) para tablas existentes.
- **Criterios de aceptación:**
1. Nuevos campos persisten y aparecen en respuesta API.
2. Migración no rompe datos existentes.
- **Dependencias:** Issue 6
- **Estimación:** 1 día

## Issue 8: Habilitar webhook GitHub firmado
- **Tipo:** feat
- **Prioridad:** alta
- **Labels sugeridas:** `webhook`, `security`, `api`, `P0`
- **Descripción:** Activar endpoint webhook hoy comentado y verificar firma HMAC SHA-256.
- **Tareas:**
1. Descomentar y refactorizar endpoint webhook.
2. Validar firma contra secret configurado.
3. Procesar evento `push` y extraer repo/commit.
4. Responder `ping` correctamente.
- **Criterios de aceptación:**
1. Webhook inválido responde 401.
2. Push válido dispara análisis.
3. Ping responde 200 con mensaje esperado.
- **Dependencias:** Issue 1
- **Estimación:** 1.5 días

## Issue 9: Implementar ejecución asíncrona del análisis
- **Tipo:** feat
- **Prioridad:** alta
- **Labels sugeridas:** `async`, `performance`, `P0`
- **Descripción:** Evitar bloqueo de request durante análisis largo.
- **Tareas:**
1. Implementar `BackgroundTasks` (MVP) o cola con Celery.
2. Separar creación de job y ejecución de job.
3. Guardar estado del job.
- **Criterios de aceptación:**
1. Endpoint responde rápido (<2s) con id de job.
2. Estado de job consultable.
3. Errores del job se reportan sin romper API principal.
- **Dependencias:** Issue 8
- **Estimación:** 2 días

## Issue 10: Crear endpoints de jobs (`status` y `result`)
- **Tipo:** feat
- **Prioridad:** media
- **Labels sugeridas:** `api`, `jobs`, `P1`
- **Descripción:** Exponer estado y resultados de análisis asíncrono.
- **Tareas:**
1. `GET /prevention/jobs/{job_id}` para estado.
2. `GET /prevention/jobs/{job_id}/result` para resultado final.
3. Modelos de respuesta consistentes.
- **Criterios de aceptación:**
1. Estados válidos: `PENDING`, `RUNNING`, `DONE`, `FAILED`.
2. Resultados disponibles al completar job.
- **Dependencias:** Issue 9
- **Estimación:** 1 día

## Issue 11: Implementar servicio DAST MVP con Docker restringido
- **Tipo:** feat
- **Prioridad:** crítica
- **Labels sugeridas:** `dast`, `docker`, `security`, `P0`
- **Descripción:** Ejecutar código en contenedor efímero con restricciones de seguridad.
- **Tareas:**
1. Crear `dynamic_analysis_service`.
2. Ejecutar contenedor con `cap_drop=ALL`, red aislada, timeout, límites de recursos.
3. Capturar artefactos de ejecución.
- **Criterios de aceptación:**
1. Cada análisis dinámico corre en contenedor aislado.
2. Timeout corta ejecuciones colgadas.
3. Se registra metadata de ejecución por análisis.
- **Dependencias:** Issue 9
- **Estimación:** 3 días

## Issue 12: Integrar captura de red (tshark) en DAST
- **Tipo:** feat
- **Prioridad:** alta
- **Labels sugeridas:** `dast`, `network`, `tshark`, `P1`
- **Descripción:** Capturar y analizar tráfico básico durante ejecución dinámica.
- **Tareas:**
1. Iniciar captura durante ventana de ejecución.
2. Parsear métricas mínimas (destinos, puertos, intentos de conexión, DNS).
3. Guardar resumen en reporte dinámico.
- **Criterios de aceptación:**
1. Reporte DAST incluye indicadores de red.
2. Fallos de captura no rompen flujo completo.
- **Dependencias:** Issue 11
- **Estimación:** 2 días

## Issue 13: Diseñar score de riesgo unificado (SAST + DAST)
- **Tipo:** feat
- **Prioridad:** alta
- **Labels sugeridas:** `risk-scoring`, `ml`, `dast`, `sast`, `P0`
- **Descripción:** Definir y aplicar fórmula única de riesgo 0-100 para dashboard.
- **Tareas:**
1. Definir pesos iniciales (ej. SAST 60 / DAST 40).
2. Implementar `risk_scoring_service`.
3. Documentar fórmula y umbrales (`LOW/MEDIUM/HIGH/CRITICAL`).
- **Criterios de aceptación:**
1. Todo análisis final devuelve `risk_score`.
2. Umbrales producen clasificación coherente.
3. Fórmula queda versionada/documentada.
- **Dependencias:** Issue 6, Issue 12
- **Estimación:** 1.5 días

## Issue 14: Estandarizar JSON final para Dashboard
- **Tipo:** feat
- **Prioridad:** media
- **Labels sugeridas:** `api-contract`, `dashboard`, `P1`
- **Descripción:** Definir contrato de salida estable para frontend/observabilidad.
- **Tareas:**
1. Especificar esquema JSON final por repositorio y por archivo.
2. Incluir score, findings, indicadores dinámicos y metadata.
3. Versionar contrato (`schema_version`).
- **Criterios de aceptación:**
1. Contrato documentado y consistente.
2. Respuestas cumplen esquema validable.
- **Dependencias:** Issue 13
- **Estimación:** 1 día

## Issue 15: Crear endpoint histórico de reportes por repositorio
- **Tipo:** feat
- **Prioridad:** media
- **Labels sugeridas:** `api`, `database`, `P1`
- **Descripción:** Exponer resultados históricos para consumo de dashboard y auditoría.
- **Tareas:**
1. Implementar `GET /prevention/reports/{repository_id}`.
2. Soportar paginación y filtros básicos.
3. Añadir orden por fecha.
- **Criterios de aceptación:**
1. Endpoint retorna reportes sin timeout con paginación.
2. Filtros por estado/lenguaje funcionan.
- **Dependencias:** Issue 14
- **Estimación:** 1 día

## Issue 16: Implementar módulo UC Defensa Activa (MVP)
- **Tipo:** feat
- **Prioridad:** alta
- **Labels sugeridas:** `defense`, `network-analyzer`, `P1`
- **Descripción:** Crear módulo para recibir telemetría de red y generar alertas de anomalía.
- **Tareas:**
1. Crear endpoint y servicio `network_analyzer`.
2. Definir modelo de evento de red de entrada.
3. Implementar reglas iniciales de anomalía.
- **Criterios de aceptación:**
1. Endpoint recibe eventos y devuelve evaluación.
2. Se generan alertas con severidad.
- **Dependencias:** Issue 14
- **Estimación:** 2 días

## Issue 17: Agregar trigger gRPC stub hacia contención/honeypot
- **Tipo:** feat
- **Prioridad:** media
- **Labels sugeridas:** `grpc`, `integration`, `P2`
- **Descripción:** Preparar integración por gRPC cuando se detecta amenaza en defensa activa.
- **Tareas:**
1. Definir interfaz/proto mínima.
2. Implementar cliente gRPC stub.
3. Activar trigger condicional por umbral.
- **Criterios de aceptación:**
1. Trigger se dispara en casos de amenaza alta.
2. Fallos de gRPC quedan en retry/log sin tumbar el flujo.
- **Dependencias:** Issue 16
- **Estimación:** 1.5 días

## Issue 18: Implementar módulo UC Contención (MVP funcional)
- **Tipo:** feat
- **Prioridad:** alta
- **Labels sugeridas:** `containment`, `incident-response`, `P1`
- **Descripción:** Crear endpoints/servicios de contención con acciones iniciales (algunas stub).
- **Tareas:**
1. Endpoint para aislar nodo comprometido (stub controlado).
2. Endpoint para bloqueo de IP/regla (stub).
3. Endpoint para iniciar restauración de backup (stub).
4. Registrar auditoría de acciones.
- **Criterios de aceptación:**
1. Acciones quedan registradas con `who/when/why`.
2. API de contención responde con estado trazable.
- **Dependencias:** Issue 17
- **Estimación:** 2 días

## Issue 19: Suite de pruebas E2E del flujo completo
- **Tipo:** test
- **Prioridad:** alta
- **Labels sugeridas:** `testing`, `e2e`, `quality`, `P0`
- **Descripción:** Cubrir flujo: webhook -> SAST -> DAST -> score -> alerta -> trigger.
- **Tareas:**
1. Crear fixtures de repositorios/casos benignos y maliciosos.
2. Probar endpoints críticos y persistencia.
3. Validar salidas y estados de job.
- **Criterios de aceptación:**
1. Pipeline E2E ejecuta en CI.
2. Casos principales pasan consistentemente.
- **Dependencias:** Issue 18
- **Estimación:** 2 días

## Issue 20: CI con lint, tests y smoke startup
- **Tipo:** chore
- **Prioridad:** media
- **Labels sugeridas:** `ci`, `quality-gate`, `P1`
- **Descripción:** Automatizar controles mínimos de calidad antes de merge.
- **Tareas:**
1. Configurar workflow CI.
2. Ejecutar lint y tests.
3. Añadir smoke test de arranque de API.
- **Criterios de aceptación:**
1. PR falla si lint/tests fallan.
2. CI corre en cada push/PR.
- **Dependencias:** Issue 19
- **Estimación:** 1 día

