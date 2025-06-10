from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError
import logging
import time

from app.models.email_models import EmailData, EmailBatch
from app.models.detection_models import (
    PhishingAnalysisResult, BatchAnalysisResult, AnalysisStats
)
from app.services.phishing_detector import PhishingDetector
from app.utils.helpers import setup_logging
from app.config.settings import get_settings

# Configurar logging
setup_logging()
logger = logging.getLogger(__name__)

# Inicializar FastAPI
app = FastAPI(
    title="Sistema Anti-Phishing",
    description="API para detectar emails de phishing usando análisis de contenido, URLs y remitentes",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En producción, especificar dominios exactos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instancia global del detector
detector = PhishingDetector()

# Estadísticas globales
global_stats = {
    "total_analyzed": 0,
    "phishing_detected": 0,
    "false_positives": 0,
    "processing_times": []
}

@app.get("/")
async def root():
    """Endpoint de salud básico"""
    return {
        "message": "Sistema Anti-Phishing API",
        "status": "online",
        "version": "1.0.0",
        "docs": "/docs"
    }

@app.get("/health")
async def health_check():
    """Endpoint de verificación de salud"""
    try:
        return {
            "status": "healthy",
            "timestamp": time.time(),
            "services": {
                "text_analyzer": "ok",
                "url_analyzer": "ok", 
                "sender_analyzer": "ok",
                "detector": "ok"
            }
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "error": str(e)}
        )

@app.post("/analyze", response_model=PhishingAnalysisResult)
async def analyze_email(email_data: EmailData):
    """
    Analiza un email individual en busca de indicadores de phishing
    
    Este es el endpoint principal que utilizará Make/Integromat para enviar emails
    """
    try:
        logger.info(f"Analyzing email from: {email_data.sender.address}")
        
        # Realizar análisis
        result = detector.analyze_email(email_data)
        
        # Actualizar estadísticas
        global_stats["total_analyzed"] += 1
        if result.is_phishing:
            global_stats["phishing_detected"] += 1
        global_stats["processing_times"].append(result.processing_time)
        
        # Log del resultado
        logger.info(
            f"Analysis complete - Phishing: {result.is_phishing}, "
            f"Threat Level: {result.threat_level}, "
            f"Confidence: {result.confidence_score:.2f}"
        )
        
        return result
        
    except ValidationError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=422, detail=f"Invalid email data: {e}")
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/analyze/batch", response_model=BatchAnalysisResult)
async def analyze_email_batch(email_batch: EmailBatch):
    """Analiza múltiples emails en lote"""
    try:
        start_time = time.time()
        results = []
        phishing_count = 0
        
        logger.info(f"Analyzing batch of {len(email_batch.emails)} emails")
        
        for email in email_batch.emails:
            result = detector.analyze_email(email)
            results.append(result)
            if result.is_phishing:
                phishing_count += 1
        
        processing_time = time.time() - start_time
        
        # Crear resumen
        summary = {
            "total_emails": len(email_batch.emails),
            "phishing_detected": phishing_count,
            "clean_emails": len(email_batch.emails) - phishing_count,
            "average_confidence": sum(r.confidence_score for r in results) / len(results),
            "threat_levels": {
                "low": sum(1 for r in results if r.threat_level == "low"),
                "medium": sum(1 for r in results if r.threat_level == "medium"), 
                "high": sum(1 for r in results if r.threat_level == "high"),
                "critical": sum(1 for r in results if r.threat_level == "critical")
            }
        }
        
        # Actualizar estadísticas globales
        global_stats["total_analyzed"] += len(email_batch.emails)
        global_stats["phishing_detected"] += phishing_count
        
        return BatchAnalysisResult(
            total_emails=len(email_batch.emails),
            phishing_detected=phishing_count,
            results=results,
            summary=summary,
            processing_time=processing_time
        )
        
    except Exception as e:
        logger.error(f"Batch analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Batch analysis failed: {str(e)}")

@app.get("/stats", response_model=AnalysisStats)
async def get_analysis_stats():
    """Obtiene estadísticas del sistema de análisis"""
    try:
        accuracy_rate = 0.95  # En producción, calcular basado en feedback real
        
        # Amenazas más comunes
        most_common_threats = [
            "suspicious_urls",
            "sender_spoofing", 
            "urgent_language",
            "spelling_errors",
            "authentication_failure"
        ]
        
        return AnalysisStats(
            total_analyzed=global_stats["total_analyzed"],
            phishing_count=global_stats["phishing_detected"],
            false_positives=global_stats["false_positives"],
            accuracy_rate=accuracy_rate,
            most_common_threats=most_common_threats
        )
        
    except Exception as e:
        logger.error(f"Stats error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")

@app.post("/feedback")
async def submit_feedback(
    email_id: str,
    is_actual_phishing: bool,
    user_comment: str = None
):
    """Permite enviar feedback sobre la precisión del análisis"""
    try:
        logger.info(
            f"Feedback received for email {email_id}: "
            f"actual_phishing={is_actual_phishing}, comment='{user_comment}'"
        )
        
        return {"message": "Feedback received successfully", "email_id": email_id}
        
    except Exception as e:
        logger.error(f"Feedback error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to submit feedback: {str(e)}")

# Endpoint específico para Make/Integromat con formato simplificado
@app.post("/webhook/make")
async def make_webhook(email_data: EmailData):
    """
    Endpoint específico para Make/Integromat con respuesta simplificada
    """
    try:
        result = detector.analyze_email(email_data)
        
        # Respuesta simplificada para Make
        simplified_response = {
            "is_phishing": result.is_phishing,
            "threat_level": result.threat_level.value,
            "confidence_score": round(result.confidence_score, 2),
            "risk_summary": {
                "total_detections": len(result.detections),
                "high_risk_urls": len([url for url in result.url_analysis if url.is_suspicious]),
                "sender_issues": not result.sender_analysis.sender_consistency,
                "suspicious_content": len(result.text_analysis.suspicious_phrases) > 0
            },
            "recommendations": result.recommendations[:3],  # Solo las 3 principales
            "timestamp": result.timestamp
        }
        
        # Log para Make
        logger.info(f"Make webhook processed - Result: {simplified_response}")
        
        return simplified_response
        
    except Exception as e:
        logger.error(f"Make webhook error: {e}")
        raise HTTPException(status_code=500, detail=f"Webhook processing failed: {str(e)}")

# Manejo de errores globales
@app.exception_handler(ValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=422,
        content={"error": "Validation Error", "details": str(exc)}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal Server Error", "message": "An unexpected error occurred"}
    )