from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings

from app.models.session import engine
from app.models.database import Base
import logging

logger = logging.getLogger(__name__)

# Create database tables
# In a real production app, this would be handled by Alembic migrations
Base.metadata.create_all(bind=engine)

# Fail-safe warning for insecure production configuration
if settings.SECRET_KEY == "temporary_dev_secret_key_change_in_prod":
    logger.warning(
        "SECRET_KEY is the built-in development default. Set a strong SECRET_KEY "
        "environment variable before deploying to production."
    )

app = FastAPI(
    title="APEX-X Platform API",
    description="Agentic APK Profiling, Exploitation Intelligence & Threat Attribution",
    version="1.0.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Configure CORS from settings (override with APEX_CORS_ORIGINS in production).
# "*" with credentials is invalid per the CORS spec, so use an explicit allow-list.
_cors_origins = settings.cors_origin_list
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?" if _cors_origins else None,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from app.api.routes import upload, auth, ws, cases, results, reports, analysis, copilot, batch

app.include_router(cases.router, prefix=settings.API_V1_STR + "/cases", tags=["cases"])
app.include_router(upload.router, prefix=settings.API_V1_STR + "/cases", tags=["cases"])
app.include_router(results.router, prefix=settings.API_V1_STR + "/cases", tags=["results"])
app.include_router(reports.router, prefix=settings.API_V1_STR + "/reports", tags=["reports"])
app.include_router(analysis.router, prefix=settings.API_V1_STR + "/analysis", tags=["analysis"])
app.include_router(auth.router, prefix=settings.API_V1_STR + "/auth", tags=["auth"])
app.include_router(ws.router, prefix=settings.API_V1_STR + "/ws", tags=["websocket"])
app.include_router(copilot.router, prefix=settings.API_V1_STR + "/copilot", tags=["copilot"])
app.include_router(batch.router, prefix=settings.API_V1_STR + "/batch", tags=["batch"])

@app.get(f"{settings.API_V1_STR}/health")
def health_check():
    return {"status": "ok", "message": "APEX-X backend is running."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8080, reload=True)
