from pydantic import BaseSettings
from typing import List, Optional
import os

class Settings(BaseSettings):
    # Configuración de la aplicación
    app_name: str = "Sistema Anti-Phishing"
    version: str = "1.0.0"
    debug: bool = False
    
    # Configuración del servidor
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Configuración de CORS
    allowed_origins: List[str] = ["*"]
    
    # Configuración de logging
    log_level: str = "INFO"
    log_file: Optional[str] = None
    
    # Configuración de la base de datos (para futuras versiones)
    database_url: Optional[str] = None
    
    # Configuración de APIs externas
    virustotal_api_key: Optional[str] = None
    urlvoid_api_key: Optional[str] = None
    
    # Configuración del detector
    max_emails_per_batch: int = 50
    max_urls_per_email: int = 20
    analysis_timeout: int = 30  # segundos
    
    # Configuración de seguridad
    api_key: Optional[str] = None
    rate_limit_per_minute: int = 100
    
    # Configuración específica de Railway
    railway_static_url: Optional[str] = None
    railway_environment: str = "production"
    
    class Config:
        env_file = ".env"
        case_sensitive = False

def get_settings() -> Settings:
    return Settings()