from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import Settings
from app.api.v1.endpoints import health, prevention, defense, containment, demo
from db.database import create_db_and_tables

# Start FastAPI application
app = FastAPI()

settings = Settings()
# Configure CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
)

# Routers API
app.include_router(health.router)
app.include_router(prevention.router)
app.include_router(defense.router)
app.include_router(containment.router)
app.include_router(demo.router)

# Endpoints
@app.get("/")
async def read_root():
    return {"message": "Welcome to VESTA Project API"}

@app.on_event("startup")
def on_startup():
    create_db_and_tables()
