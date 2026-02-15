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

## Notas
- Los modelos ML deben estar disponibles en `ml_models/`.
- Los repositorios clonados se almacenan en `~/vesta_cloned_repos`.
