# VESTA - Guía Operativa Completa de Defensa Activa + Contención + Honeypot (Issue 18)

## 1) Propósito del documento
Este documento describe, de extremo a extremo, cómo funciona la arquitectura de **Defensa Activa** y **Contención** en VESTA, cómo opera en modo manual/automático, qué nivel de seguridad ofrece actualmente, cómo evaluar su efectividad y cómo evolucionarla a producción.

Incluye:
- qué hace cada módulo;
- cómo interactúan entre sí;
- cómo se dispara contención;
- dónde entra el honeypot;
- cómo probar cada flujo paso a paso;
- limitaciones actuales (MVP) y ruta de endurecimiento.

---

## 2) Resumen ejecutivo (qué resuelve el Issue 18)
El Issue 18 implementa el módulo de **Contención** con acciones iniciales tipo stub, pero con trazabilidad completa de auditoría:

1. `POST /containment/isolate-node` (aislamiento de nodo comprometido, simulado).
2. `POST /containment/block-ip` (bloqueo de IP/regla, simulado).
3. `POST /containment/restore-backup` (restauración de backup, simulada).
4. `POST /containment/deploy-honeypot` (despliegue de honeypot/decepción, simulado).
5. Auditoría persistida en BD con `who/when/why` + estado + detalles técnicos.
6. Consulta y gestión de acciones:
   - `GET /containment/actions`
   - `GET /containment/actions/{id}`
   - `PATCH /containment/actions/{id}/status`

Resultado: ya existe un ciclo operativo **detección -> decisión -> contención -> auditoría** sin depender aún de ejecución destructiva real.

---

## 3) Arquitectura funcional

## 3.1 Módulos involucrados
- **Defensa activa** (`/defense`):
  - ingesta telemetría de logs/eventos;
  - correlación contextual por ventanas de tiempo;
  - reglas de comportamiento;
  - alertas y score;
  - trigger gRPC condicional hacia contención/honeypot.

- **Contención** (`/containment`) [Issue 18]:
  - recibe solicitudes de acción;
  - valida payload operativo;
  - ejecuta en modo `STUB` (simulación controlada);
  - registra auditoría completa y estado de operación.

- **gRPC trigger (Issue 17)**:
  - defensa notifica al orquestador de contención/honeypot cuando el riesgo supera umbral.
  - resiliente: si gRPC falla, el análisis no se cae.

## 3.2 Flujo operacional integrado
1. Entra un evento de seguridad por `/defense/events`.
2. Motor de defensa evalúa reglas y genera alertas.
3. Se calcula `action_recommended`.
4. Si cumple umbral y política, se dispara trigger gRPC.
5. Operador SOC (o integración automática) ejecuta acción en `/containment/*`.
6. Toda acción queda registrada en `containment_action_audit`.
7. El estado puede transicionar durante el ciclo IR (`REQUESTED`, `SIMULATED_EXECUTED`, `FAILED`, etc.).

---

## 4) Defensa activa: cómo decide y cuándo actúa

## 4.1 Qué evalúa defensa
La defensa correlaciona eventos por contexto (`source_system` + identidad por `source_ip`/`host_id`/`user_id`) y aplica reglas base:
- brute force de autenticación;
- patrón de movimiento lateral;
- comandos sospechosos;
- exfiltración de datos;
- patrón comportamental tipo ransomware.

## 4.2 Resultado de defensa por evento
Devuelve:
- alertas detonadas;
- score/confidence;
- `action_recommended` (`NONE`, `MANUAL_REVIEW`, `ESCALATE_SOC`, `TRIGGER_CONTAINMENT`);
- estado del trigger gRPC (`containment_trigger`).

## 4.3 Trigger gRPC condicional
Defensa dispara gRPC solo si:
- `action_recommended in {ESCALATE_SOC, TRIGGER_CONTAINMENT}`
- `max_alert_score >= DEFENSE_GRPC_TRIGGER_MIN_SCORE`

Esto reduce ruido y evita escalar eventos de baja señal.

---

## 5) Contención (Issue 18): diseño y comportamiento

## 5.1 Principios operativos
- **Seguridad por defecto**: acciones en modo `STUB`, no destructivas.
- **Auditabilidad total**: toda petición se persiste con trazabilidad.
- **Validación estricta**: datos críticos (ej. IP, campos obligatorios) se validan antes de registrar ejecución.
- **Transición de estado controlada**: permite ciclo de vida operativo real.

## 5.2 Tabla de auditoría
Tabla: `containment_action_audit`

Campos clave:
- contexto: `repository_id`, `source_alert_id`, `correlation_id`;
- acción: `action_type`, `target_type`, `target_value`;
- gobernanza: `reason`, `requested_by`;
- ejecución: `status`, `execution_mode`, `provider`, `details`, `error_message`;
- tiempos: `requested_at`, `executed_at`, `updated_at`.

Esto permite responder auditorías tipo:
- quién ordenó la acción;
- por qué se ejecutó;
- contra qué activo se aplicó;
- cuál fue el resultado y cuándo.

---

## 6) Endpoints de contención (detalle funcional)

## 6.1 `POST /containment/isolate-node`
Uso:
- aislar host comprometido en cuarentena lógica.

Entrada mínima:
- `host_id`, `reason`, `requested_by`.

Salida:
- acción auditada con plan de ejecución simulado (quarantine ACL, control de egress, etc.).

## 6.2 `POST /containment/block-ip`
Uso:
- bloquear IP maliciosa de forma temporal/operativa.

Entrada mínima:
- `ip_address`, `reason`, `requested_by`.

Validaciones:
- IP válida (IPv4/IPv6),
- `direction` en `{INBOUND, OUTBOUND, BOTH}`.

## 6.3 `POST /containment/restore-backup`
Uso:
- iniciar runbook de recuperación post-incidente.

Entrada mínima:
- `asset_id`, `reason`, `requested_by`.

Detalle auditado:
- estrategia de restore,
- validación hash previa,
- cleanroom restore.

## 6.4 `POST /containment/deploy-honeypot`
Uso:
- desplegar activo señuelo para capturar TTPs y telemetría de atacante.

Entrada mínima:
- `decoy_target`, `reason`, `requested_by`.

Incluye:
- perfil honeypot (`honeypot_profile`),
- TTL operacional,
- comportamiento de captura (metadata en `details.honey_pot_behavior`).

## 6.5 `GET /containment/actions`
Uso:
- consultar bitácora operacional con filtros/paginación.

Filtros principales:
- `action_type`, `status`, `requested_by`, `repository_id`, `source_alert_id`.

## 6.6 `GET /containment/actions/{id}`
Uso:
- ver trazabilidad completa de una acción puntual.

## 6.7 `PATCH /containment/actions/{id}/status`
Uso:
- actualizar estado de ciclo operativo:
  - `REQUESTED`
  - `SIMULATED_EXECUTED`
  - `FAILED`
  - `ROLLED_BACK`
  - `CANCELED`

---

## 7) Honeypot: dónde está y cómo actúa en este MVP

## 7.1 Estado actual
En Issue 18 el honeypot está implementado como **orquestación simulada y auditada**:
- endpoint: `POST /containment/deploy-honeypot`;
- se registra perfil, TTL, zona y plan de despliegue;
- no levanta aún infraestructura de engaño real en runtime.

## 7.2 Qué sí entrega hoy
- control de proceso;
- trazabilidad forense;
- estandarización del runbook de engaño;
- integración natural con SOC y SIEM.

## 7.3 Qué falta para honeypot “real”
- aprovisionamiento automatizado (containers/VM);
- segmentación de red dedicada de engaño;
- forwarding seguro de telemetría;
- playbooks automáticos de enriquecimiento IOC/TTP;
- hardening anti-escape y aislamiento de señuelos.

---

## 8) Nivel de seguridad que ofrece actualmente

## 8.1 Cobertura actual (MVP endurecido)
- **Detección**: media-alta (correlación contextual + reglas comportamentales).
- **Respuesta**: media (acciones stub con control operativo).
- **Trazabilidad**: alta (auditoría persistente completa).
- **Automatización IR**: media (trigger gRPC + runbooks simulados).

## 8.2 Clasificación de madurez
- Estado actual: **IR Assistive Automation** (asistencia fuerte al SOC, ejecución real aún parcial).
- Para llegar a “Full Automated Containment” se requiere:
  - ejecutores reales (firewall/EDR/orchestrator),
  - IAM de servicio + mTLS,
  - controles de aprobación y rollback automatizado.

---

## 9) Cómo evaluar el sistema (metodología recomendada)

## 9.1 Pruebas funcionales mínimas
1. Ingesta de eventos benignos y maliciosos.
2. Confirmar creación de alertas por regla.
3. Validar trigger gRPC condicional.
4. Ejecutar acciones de contención stub.
5. Confirmar persistencia y consulta de auditoría.

## 9.2 Pruebas de resiliencia
1. Apagar endpoint gRPC y verificar que defensa no cae.
2. Inyectar payloads inválidos en contención y validar errores 400.
3. Verificar consistencia de estados bajo concurrencia.

## 9.3 KPIs operativos sugeridos
- MTTD: tiempo detección promedio por evento crítico.
- MTTR (simulado): tiempo desde alerta crítica a acción registrada.
- Trigger success rate gRPC (`SENT` vs `FAILED`).
- Ratio de acciones `FAILED` por tipo.
- Tiempo de cierre de acciones y alertas.

---

## 10) Guía paso a paso para operación local

## 10.1 Levantar servicios
1. Activar entorno:
```powershell
.venv\Scripts\Activate.ps1
```
2. Instalar dependencias:
```powershell
pip install -r requirements.txt
```
3. Levantar mock gRPC (issue 17):
```powershell
python scripts/mock_containment_grpc_server.py --host 127.0.0.1 --port 50051
```
4. Levantar API:
```powershell
uvicorn app.main:app --reload
```

## 10.2 Probar defensa + trigger
```powershell
$uri = "http://127.0.0.1:8000/defense/events"
1..6 | ForEach-Object {
  $payload = @{
    repository_id = 7
    source_system = "EDR"
    source_ip = "10.10.10.5"
    host_id = "host-a"
    user_id = "alice"
    event_type = "AUTH_FAILURE"
    severity = "MEDIUM"
    message = "failed login for user alice"
    event_context = @{}
    raw_payload = @{ event_id = "bf-alice-$($_)" }
  } | ConvertTo-Json -Depth 8

  Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Body $payload
}
```

## 10.3 Ejecutar contención manual (ejemplo block-ip)
```powershell
$payload = @{
  repository_id = 7
  source_alert_id = 1
  correlation_id = "corr-123"
  reason = "Detected outbound C2 communication"
  requested_by = "soc.lead"
  ip_address = "185.12.12.12"
  direction = "BOTH"
  duration_minutes = 120
  rule_scope = "EDGE_FIREWALL"
} | ConvertTo-Json -Depth 8

Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/containment/block-ip" `
  -ContentType "application/json" `
  -Body $payload
```

## 10.4 Consultar auditoría
```powershell
Invoke-RestMethod -Method Get "http://127.0.0.1:8000/containment/actions?page=1&page_size=50"
```

---

## 11) Casos de uso aplicables
- SOC de medianas organizaciones sin SOAR maduro.
- Programas de threat hunting con respuesta controlada.
- Simulaciones de IR y entrenamiento de blue team.
- Entornos académicos/laboratorio para practicar detección + contención.

---

## 12) Riesgos y límites actuales
- Contención real no está aplicada (modo stub).
- Honeypot real no se despliega automáticamente aún.
- Falta control de aprobación multinivel (four-eyes) para acciones críticas.
- Falta mTLS + autenticación fuerte en integración gRPC de producción.

---

## 13) Roadmap técnico recomendado (post-Issue 18)
1. Integrar ejecutores reales:
   - EDR isolate API,
   - firewall controller,
   - backup orchestrator.
2. Implementar approval workflow por severidad.
3. Firmar requests gRPC con mTLS y service identity.
4. Añadir rollback programado y expiración automática de reglas temporales.
5. Integrar honeypot runtime (containers aislados + collector SIEM).

---

## 14) Conclusión operativa
Con Issue 18, VESTA pasa de solo detectar a poder **orquestar respuesta** de forma gobernada:
- conserva trazabilidad completa;
- minimiza riesgo operativo con ejecución no destructiva;
- prepara el terreno para contención real en el siguiente ciclo.

El módulo queda listo para transición gradual de `STUB` a ejecución real sin perder control de seguridad ni auditoría.
