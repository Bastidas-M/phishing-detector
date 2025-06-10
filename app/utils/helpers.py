import logging
import sys
from typing import Dict, Any
import json
from datetime import datetime

def setup_logging(log_level: str = "INFO", log_file: str = None):
    """Configura el sistema de logging"""
    
    # Configurar formato
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Configurar handler para consola
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    
    # Configurar handler para archivo si se especifica
    handlers = [console_handler]
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)
    
    # Configurar logger principal
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        handlers=handlers,
        force=True
    )
    
    # Configurar loggers específicos
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("fastapi").setLevel(logging.INFO)

def create_response(
    success: bool,
    data: Any = None,
    message: str = None,
    error: str = None
) -> Dict[str, Any]:
    """Crea una respuesta estandarizada para la API"""
    
    response = {
        "success": success,
        "timestamp": datetime.now().isoformat()
    }
    
    if data is not None:
        response["data"] = data
    
    if message:
        response["message"] = message
    
    if error:
        response["error"] = error
    
    return response

def sanitize_email_content(content: str, max_length: int = 10000) -> str:
    """Sanitiza el contenido de un email para análisis seguro"""
    if not content:
        return ""
    
    # Limitar longitud
    if len(content) > max_length:
        content = content[:max_length] + "..."
    
    # Remover caracteres de control peligrosos
    control_chars = ['\\x00', '\\x01', '\\x02', '\\x03', '\\x04', '\\x05']
    for char in control_chars:
        content = content.replace(char, '')
    
    return content.strip()

def extract_domain_info(domain: str) -> Dict[str, Any]:
    """Extrae información básica de un dominio"""
    try:
        import tldextract
        extracted = tldextract.extract(domain)
        
        return {
            "subdomain": extracted.subdomain,
            "domain": extracted.domain,
            "suffix": extracted.suffix,
            "fqdn": extracted.fqdn,
            "registered_domain": extracted.registered_domain
        }
    except Exception as e:
        logging.error(f"Error extracting domain info for {domain}: {e}")
        return {"error": str(e)}

def calculate_text_similarity(text1: str, text2: str) -> float:
    """Calcula similitud básica entre dos textos"""
    try:
        from difflib import SequenceMatcher
        
        # Normalizar textos
        text1 = text1.lower().strip()
        text2 = text2.lower().strip()
        
        if not text1 or not text2:
            return 0.0
        
        # Calcular similitud
        similarity = SequenceMatcher(None, text1, text2).ratio()
        return round(similarity, 2)
        
    except Exception:
        return 0.0

def is_valid_email(email: str) -> bool:
    """Valida formato básico de email"""
    import re
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def format_file_size(size_bytes: int) -> str:
    """Formatea el tamaño de archivo en formato legible"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB"]
    import math
    
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    
    return f"{s} {size_names[i]}"

def clean_html_content(html: str) -> str:
    """Limpia contenido HTML básico para análisis"""
    import re
    
    if not html:
        return ""
    
    # Remover scripts y estilos
    html = re.sub(r'<script.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<style.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)
    
    # Remover comentarios HTML
    html = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)
    
    # Remover tags HTML pero mantener contenido
    html = re.sub(r'<[^>]+>', ' ', html)
    
    # Limpiar espacios múltiples
    html = re.sub(r'\s+', ' ', html)
    
    # Decodificar entidades HTML básicas
    html = html.replace('&nbsp;', ' ')
    html = html.replace('&amp;', '&')
    html = html.replace('&lt;', '<')
    html = html.replace('&gt;', '>')
    html = html.replace('&quot;', '"')
    html = html.replace('&#39;', "'")
    
    return html.strip()

def log_analysis_result(result: Any, logger: logging.Logger):
    """Log estructurado de resultados de análisis"""
    try:
        summary = {
            "is_phishing": result.is_phishing,
            "threat_level": result.threat_level,
            "confidence_score": round(result.confidence_score, 2),
            "detections_count": len(result.detections),
            "processing_time": round(result.processing_time, 3)
        }
        
        logger.info(f"Analysis Result: {json.dumps(summary)}")
        
    except Exception as e:
        logger.error(f"Error logging analysis result: {e}")

def validate_make_webhook_data(data: Dict[str, Any]) -> bool:
    """Valida que los datos del webhook de Make tengan el formato correcto"""
    required_fields = ['date', 'subject', 'text', 'from', 'to']
    
    try:
        # Verificar campos requeridos
        for field in required_fields:
            if field not in data:
                return False
        
        # Verificar estructura del remitente
        if not isinstance(data['from'], dict) or 'address' not in data['from']:
            return False
        
        # Verificar estructura de destinatarios
        if not isinstance(data['to'], list) or len(data['to']) == 0:
            return False
        
        return True
        
    except Exception:
        return False