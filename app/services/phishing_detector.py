import time
from datetime import datetime
from typing import List, Dict, Any
from app.models.email_models import EmailData
from app.models.detection_models import (
    PhishingAnalysisResult, ThreatLevel, Detection, DetectionCategory
)
from app.services.text_analyzer import TextAnalyzer
from app.services.url_analyzer import URLAnalyzer
from app.services.sender_analyzer import SenderAnalyzer

class PhishingDetector:
    def __init__(self):
        self.text_analyzer = TextAnalyzer()
        self.url_analyzer = URLAnalyzer()
        self.sender_analyzer = SenderAnalyzer()
        
        # Pesos para el cálculo del score final
        self.weights = {
            'sender_analysis': 0.35,      # 35% - Autenticación y reputación del remitente
            'url_analysis': 0.30,         # 30% - URLs sospechosas
            'text_analysis': 0.25,        # 25% - Contenido del texto
            'attachment_analysis': 0.10   # 10% - Archivos adjuntos
        }
        
        # Umbrales para clasificación de amenazas
        self.threat_thresholds = {
            'low': 0.3,
            'medium': 0.5,
            'high': 0.7,
            'critical': 0.85
        }

    def analyze_email(self, email: EmailData) -> PhishingAnalysisResult:
        """Analiza un email completo en busca de indicadores de phishing"""
        start_time = time.time()
        detections = []
        
        # 1. Análisis del remitente
        sender_analysis = self.sender_analyzer.analyze_sender(email.sender, email.headers)
        sender_detections = self._evaluate_sender_analysis(sender_analysis)
        detections.extend(sender_detections)
        
        # 2. Análisis de URLs
        urls = self.url_analyzer.extract_urls(email.text, email.html)
        url_analysis = self.url_analyzer.analyze_urls(urls)
        url_detections = self._evaluate_url_analysis(url_analysis)
        detections.extend(url_detections)
        
        # 3. Análisis de texto
        text_analysis = self.text_analyzer.analyze_text(email.text, email.html, email.subject)
        text_detections = self._evaluate_text_analysis(text_analysis)
        detections.extend(text_detections)
        
        # 4. Análisis de adjuntos
        attachment_detections = self._analyze_attachments(email.attachments)
        detections.extend(attachment_detections)
        
        # 5. Calcular score final y determinar si es phishing
        confidence_score = self._calculate_confidence_score(
            sender_analysis, url_analysis, text_analysis, len(attachment_detections)
        )
        
        threat_level = self._determine_threat_level(confidence_score)
        is_phishing = confidence_score >= self.threat_thresholds['medium']
        
        # 6. Generar recomendaciones
        recommendations = self._generate_recommendations(detections, threat_level)
        
        processing_time = time.time() - start_time
        
        return PhishingAnalysisResult(
            email_id=getattr(email, 'id', None),
            is_phishing=is_phishing,
            threat_level=threat_level,
            confidence_score=confidence_score,
            detections=detections,
            url_analysis=url_analysis,
            text_analysis=text_analysis,
            sender_analysis=sender_analysis,
            processing_time=processing_time,
            timestamp=datetime.now().isoformat(),
            recommendations=recommendations
        )

    def _evaluate_sender_analysis(self, analysis) -> List[Detection]:
        """Evalúa el análisis del remitente y genera detecciones"""
        detections = []
        
        if analysis.is_spoofed:
            detections.append(Detection(
                category=DetectionCategory.SENDER_SPOOFING,
                severity=ThreatLevel.HIGH,
                description="Posible suplantación del remitente detectada",
                confidence=0.8,
                details={
                    "domain_reputation": analysis.domain_reputation,
                    "authentication_failures": {
                        "spf": not analysis.spf_pass,
                        "dkim": not analysis.dkim_pass,
                        "dmarc": not analysis.dmarc_pass
                    }
                }
            ))
        
        if analysis.domain_reputation in ['suspicious', 'malicious']:
            severity = ThreatLevel.HIGH if analysis.domain_reputation == 'malicious' else ThreatLevel.MEDIUM
            detections.append(Detection(
                category=DetectionCategory.FAKE_DOMAINS,
                severity=severity,
                description=f"Dominio con reputación {analysis.domain_reputation}",
                confidence=0.7,
                details={"domain_reputation": analysis.domain_reputation}
            ))
        
        # Verificar fallos de autenticación
        auth_failures = []
        if not analysis.spf_pass:
            auth_failures.append("SPF")
        if not analysis.dkim_pass:
            auth_failures.append("DKIM")
        if not analysis.dmarc_pass:
            auth_failures.append("DMARC")
        
        if len(auth_failures) >= 2:
            detections.append(Detection(
                category=DetectionCategory.AUTHENTICATION_FAILURE,
                severity=ThreatLevel.MEDIUM,
                description=f"Fallos de autenticación: {', '.join(auth_failures)}",
                confidence=0.6,
                details={"failed_methods": auth_failures}
            ))
        
        return detections

    def _evaluate_url_analysis(self, url_analyses) -> List[Detection]:
        """Evalúa el análisis de URLs y genera detecciones"""
        detections = []
        
        for url_analysis in url_analyses:
            if url_analysis.is_suspicious:
                severity = ThreatLevel.HIGH if len(url_analysis.reasons) > 2 else ThreatLevel.MEDIUM
                
                detections.append(Detection(
                    category=DetectionCategory.SUSPICIOUS_URLS,
                    severity=severity,
                    description=f"URL sospechosa detectada: {url_analysis.url[:50]}...",
                    confidence=min(0.9, 0.4 + (len(url_analysis.reasons) * 0.15)),
                    details={
                        "url": url_analysis.url,
                        "reasons": url_analysis.reasons,
                        "is_shortened": url_analysis.is_shortened,
                        "redirects_to": url_analysis.redirects_to
                    }
                ))
        
        return detections

    def _evaluate_text_analysis(self, analysis) -> List[Detection]:
        """Evalúa el análisis de texto y genera detecciones"""
        detections = []
        
        # Verificar errores ortográficos excesivos
        if analysis.spelling_errors > 5:
            severity = ThreatLevel.HIGH if analysis.spelling_errors > 10 else ThreatLevel.MEDIUM
            detections.append(Detection(
                category=DetectionCategory.SPELLING,
                severity=severity,
                description=f"Múltiples errores ortográficos detectados ({analysis.spelling_errors})",
                confidence=min(0.8, 0.3 + (analysis.spelling_errors * 0.05)),
                details={"spelling_errors_count": analysis.spelling_errors}
            ))
        
        # Verificar palabras de urgencia
        if len(analysis.urgency_keywords) > 3:
            detections.append(Detection(
                category=DetectionCategory.URGENT_LANGUAGE,
                severity=ThreatLevel.MEDIUM,
                description="Lenguaje urgente detectado",
                confidence=min(0.7, 0.4 + (len(analysis.urgency_keywords) * 0.1)),
                details={
                    "urgency_keywords": analysis.urgency_keywords,
                    "count": len(analysis.urgency_keywords)
                }
            ))
        
        # Verificar frases sospechosas
        if analysis.suspicious_phrases:
            detections.append(Detection(
                category=DetectionCategory.SOCIAL_ENGINEERING,
                severity=ThreatLevel.HIGH,
                description="Frases típicas de ingeniería social detectadas",
                confidence=0.8,
                details={
                    "suspicious_phrases": analysis.suspicious_phrases,
                    "count": len(analysis.suspicious_phrases)
                }
            ))
        
        # Verificar gramática pobre
        if analysis.grammar_score < 0.4:
            detections.append(Detection(
                category=DetectionCategory.SPELLING,
                severity=ThreatLevel.MEDIUM,
                description="Calidad gramatical muy baja",
                confidence=0.6,
                details={"grammar_score": analysis.grammar_score}
            ))
        
        # Verificar inconsistencia de idioma
        if not analysis.language_consistency:
            detections.append(Detection(
                category=DetectionCategory.SPELLING,
                severity=ThreatLevel.LOW,
                description="Inconsistencia en el idioma del mensaje",
                confidence=0.5,
                details={"language_consistency": False}
            ))
        
        return detections

    def _analyze_attachments(self, attachments) -> List[Detection]:
        """Analiza archivos adjuntos en busca de amenazas"""
        detections = []
        
        if not attachments:
            return detections
        
        dangerous_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js',
            '.jar', '.zip', '.rar', '.7z', '.doc', '.docm', '.xls', '.xlsm'
        ]
        
        for attachment in attachments:
            filename = attachment.get('filename', '').lower()
            
            # Verificar extensiones peligrosas
            if any(filename.endswith(ext) for ext in dangerous_extensions):
                severity = ThreatLevel.CRITICAL if filename.endswith(('.exe', '.scr', '.bat')) else ThreatLevel.HIGH
                
                detections.append(Detection(
                    category=DetectionCategory.MALICIOUS_ATTACHMENTS,
                    severity=severity,
                    description=f"Archivo adjunto potencialmente peligroso: {filename}",
                    confidence=0.8,
                    details={
                        "filename": filename,
                        "size": attachment.get('size', 0),
                        "content_type": attachment.get('content_type', '')
                    }
                ))
        
        return detections

    def _calculate_confidence_score(self, sender_analysis, url_analyses, text_analysis, attachment_threats) -> float:
        """Calcula el score de confianza final"""
        scores = {
            'sender': 0.0,
            'url': 0.0,
            'text': 0.0,
            'attachment': 0.0
        }
        
        # Score del remitente
        if sender_analysis.is_spoofed:
            scores['sender'] += 0.8
        elif sender_analysis.domain_reputation == 'malicious':
            scores['sender'] += 0.9
        elif sender_analysis.domain_reputation == 'suspicious':
            scores['sender'] += 0.6
        
        auth_failures = sum([
            not sender_analysis.spf_pass,
            not sender_analysis.dkim_pass,
            not sender_analysis.dmarc_pass
        ])
        scores['sender'] += auth_failures * 0.2
        
        # Score de URLs
        if url_analyses:
            suspicious_urls = sum(1 for url in url_analyses if url.is_suspicious)
            url_ratio = suspicious_urls / len(url_analyses)
            scores['url'] = min(1.0, url_ratio + 0.3)
        
        # Score de texto
        text_score = 0.0
        if text_analysis.spelling_errors > 5:
            text_score += min(0.6, text_analysis.spelling_errors * 0.05)
        if len(text_analysis.urgency_keywords) > 3:
            text_score += min(0.4, len(text_analysis.urgency_keywords) * 0.1)
        if text_analysis.suspicious_phrases:
            text_score += 0.5
        if text_analysis.grammar_score < 0.4:
            text_score += 0.3
        
        scores['text'] = min(1.0, text_score)
        
        # Score de adjuntos
        scores['attachment'] = min(1.0, attachment_threats * 0.5)
        
        # Calcular score ponderado final
        final_score = (
            scores['sender'] * self.weights['sender_analysis'] +
            scores['url'] * self.weights['url_analysis'] +
            scores['text'] * self.weights['text_analysis'] +
            scores['attachment'] * self.weights['attachment_analysis']
        )
        
        return min(1.0, final_score)

    def _determine_threat_level(self, confidence_score: float) -> ThreatLevel:
        """Determina el nivel de amenaza basado en el score de confianza"""
        if confidence_score >= self.threat_thresholds['critical']:
            return ThreatLevel.CRITICAL
        elif confidence_score >= self.threat_thresholds['high']:
            return ThreatLevel.HIGH
        elif confidence_score >= self.threat_thresholds['medium']:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def _generate_recommendations(self, detections: List[Detection], threat_level: ThreatLevel) -> List[str]:
        """Genera recomendaciones basadas en las detecciones"""
        recommendations = []
        
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            recommendations.append("🚨 NO abrir enlaces ni descargar archivos adjuntos")
            recommendations.append("🚨 NO proporcionar información personal o financiera")
            recommendations.append("🚨 Reportar este email como phishing")
        
        # Recomendaciones específicas por tipo de detección
        detection_categories = [d.category for d in detections]
        
        if DetectionCategory.SUSPICIOUS_URLS in detection_categories:
            recommendations.append("⚠️ Verificar URLs manualmente antes de hacer clic")
            recommendations.append("💡 Escribir la URL directamente en el navegador")
        
        if DetectionCategory.SENDER_SPOOFING in detection_categories:
            recommendations.append("📧 Verificar la identidad del remitente por otro medio")
            recommendations.append("🔍 Revisar la dirección de email completa")
        
        if DetectionCategory.MALICIOUS_ATTACHMENTS in detection_categories:
            recommendations.append("📎 NO descargar ni ejecutar archivos adjuntos")
            recommendations.append("🛡️ Escanear archivos con antivirus actualizado")
        
        if DetectionCategory.URGENT_LANGUAGE in detection_categories:
            recommendations.append("⏰ Desconfiar de mensajes que crean urgencia artificial")
            recommendations.append("📞 Contactar directamente a la organización para verificar")
        
        if DetectionCategory.AUTHENTICATION_FAILURE in detection_categories:
            recommendations.append("🔐 Email sin autenticación válida - alto riesgo")
        
        # Recomendaciones generales para todos los niveles
        if threat_level != ThreatLevel.LOW:
            recommendations.append("🔍 Verificar la información con la organización oficial")
            recommendations.append("📚 Capacitarse sobre técnicas de phishing")
        
        return recommendations