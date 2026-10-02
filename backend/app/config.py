from pydantic_settings import BaseSettings
import os
from dotenv import load_dotenv
from pathlib import Path

# backend/ directory (config.py is backend/app/config.py)
BASE_DIR = Path(__file__).resolve().parent.parent
env_path = BASE_DIR.parent / '.env'
load_dotenv(dotenv_path=env_path)

class Settings(BaseSettings):
    PROJECT_NAME: str = "APEX-X Backend API"
    API_V1_STR: str = "/api/v1"

    # Centralised, absolute data locations (single source of truth)
    DATA_DIR: str = os.getenv("APEX_DATA_DIR", str(BASE_DIR / "data"))

    @property
    def CASES_DIR(self) -> str:
        return os.path.join(self.DATA_DIR, "cases")

    @property
    def REPORTS_DIR(self) -> str:
        return os.path.join(self.DATA_DIR, "reports")

    @property
    def CHROMA_DIR(self) -> str:
        return os.path.join(self.DATA_DIR, "chroma")
    
    POSTGRES_USER: str = "apex"
    POSTGRES_PASSWORD: str = "apexpassword"
    POSTGRES_DB: str = "apex_db"
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: str = "5432"

    SECRET_KEY: str = os.getenv("SECRET_KEY", "temporary_dev_secret_key_change_in_prod")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7
    
    SQLALCHEMY_DATABASE_URI: str = os.getenv(
        "DATABASE_URL", f"sqlite:///{(BASE_DIR / 'apex_x.db').as_posix()}"
    )
    
    # Redis & Celery
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: str = os.getenv("REDIS_PORT", "6379")

    # Ollama (Local LLM)
    OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://172.16.128.57:11434")
    OLLAMA_MODEL_CODER: str = os.getenv("OLLAMA_MODEL_CODER", "qwen2.5-coder:7b")
    OLLAMA_MODEL_SECURITY: str = os.getenv("OLLAMA_MODEL_SECURITY", "qwen2.5-coder:7b")
    OLLAMA_TIMEOUT: int = 300  # 5 min for slow machines

    # Neo4j
    NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "apexpassword")

    # ChromaDB
    CHROMADB_HOST: str = os.getenv("CHROMADB_HOST", "localhost")
    CHROMADB_PORT: int = int(os.getenv("CHROMADB_PORT", "8000"))
    
    # Feature Toggles
    ALLOW_BAAS_NETWORK_ENRICHMENT: bool = os.getenv("ALLOW_BAAS_NETWORK_ENRICHMENT", "False").lower() in ("true", "1", "t")

    # CORS — comma-separated allowed origins (set APEX_CORS_ORIGINS in production)
    CORS_ORIGINS: str = os.getenv(
        "APEX_CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,http://localhost:8080",
    )

    @property
    def cors_origin_list(self) -> list:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    # Threat Intelligence
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    IPINFO_API_TOKEN: str = os.getenv("IPINFO_API_TOKEN", "")
    
    @property
    def CELERY_BROKER_URL(self) -> str:
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/0"
        
    @property
    def CELERY_RESULT_BACKEND(self) -> str:
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/0"

    model_config = {"case_sensitive": True, "extra": "ignore"}

settings = Settings()
