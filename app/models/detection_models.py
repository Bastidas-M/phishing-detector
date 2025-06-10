from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from enum import Enum

class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class DetectionCategory(str, Enum):
    SPELLING = "spelling_errors"
    SUSPICIOUS_URLS = "suspicious_urls"
    SENDER_SPOOFING = "sender_spoofing"
    URGENT_LANGUAGE = "urgent_language"
    FAKE_DOMAINS = "fake_domains"
    MALICIOUS_ATTACHMENTS = "malicious_attachments"
    SOCIAL_ENGINEERING = "social_engineering"
    AUTHENTICATION_FAILURE = "authentication_failure"

class Detection(BaseModel):
    category: DetectionCategory
    severity: ThreatLevel
    description: str
    details: Optional[Dict[str, Any]] = {}
    confidence: float = Field(ge=0.0, le=1.0)  # 0-1 confidence score

class URLAnalysis(BaseModel):
    url: str
    is_suspicious: bool
    reasons: List[str] = []
    domain_age: Optional[int] = None
    is_shortened: bool = False
    redirects_to: Optional[str] = None

class TextAnalysis(BaseModel):
    spelling_errors: int
    grammar_score: float = Field(ge=0.0, le=1.0)
    urgency_keywords: List[str] = []
    suspicious_phrases: List[str] = []
    language_consistency: bool = True

class SenderAnalysis(BaseModel):
    is_spoofed: bool
    domain_reputation: str  # "good", "unknown", "suspicious", "malicious"
    spf_pass: bool
    dkim_pass: bool
    dmarc_pass: bool
    sender_consistency: bool

class PhishingAnalysisResult(BaseModel):
    email_id: Optional[str] = None
    is_phishing: bool
    threat_level: ThreatLevel
    confidence_score: float = Field(ge=0.0, le=1.0)
    detections: List[Detection] = []
    
    # Análisis detallados
    url_analysis: List[URLAnalysis] = []
    text_analysis: TextAnalysis
    sender_analysis: SenderAnalysis
    
    # Metadatos
    processing_time: float
    timestamp: str
    
    # Recomendaciones
    recommendations: List[str] = []
    
class BatchAnalysisResult(BaseModel):
    """Resultado del análisis de múltiples emails"""
    total_emails: int
    phishing_detected: int
    results: List[PhishingAnalysisResult]
    summary: Dict[str, Any]
    processing_time: float

class AnalysisStats(BaseModel):
    """Estadísticas de análisis"""
    total_analyzed: int
    phishing_count: int
    false_positives: int
    accuracy_rate: float
    most_common_threats: List[str]