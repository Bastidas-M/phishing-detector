import re
import unicodedata
from typing import List, Dict, Set
from textblob import TextBlob
from app.models.detection_models import TextAnalysis

class TextAnalyzer:
    def __init__(self):
        # Palabras clave que indican urgencia/phishing
        self.urgency_keywords = {
            'spanish': [
                'urgente', 'inmediato', 'expira', 'suspendido', 'bloqueado',
                'verificar', 'confirmar', 'actualizar', 'caducado', 'emergencia',
                'último aviso', 'acción requerida', 'cuenta bloqueada',
                'suspensión', 'verificación inmediata', 'click aquí',
                'haga clic', 'premio', 'ganador', 'lotería', 'herencia'
            ],
            'english': [
                'urgent', 'immediate', 'expires', 'suspended', 'blocked',
                'verify', 'confirm', 'update', 'expired', 'emergency',
                'final notice', 'action required', 'account suspended',
                'click here', 'winner', 'congratulations', 'lottery',
                'inheritance', 'prince', 'million dollars'
            ]
        }
        
        # Frases sospechosas comunes en phishing
        self.suspicious_phrases = [
            'click here to verify',
            'su cuenta será suspendida',
            'verificar su identidad',
            'actualizar información',
            'click en el enlace',
            'confirmar su cuenta',
            'premio pendiente',
            'transferencia de dinero',
            'herencia millonaria',
            'príncipe nigeriano',
            'cuenta bancaria bloqueada',
            'tarjeta de crédito suspendida'
        ]
        
        # Patrones comunes de errores ortográficos en phishing
        self.common_misspellings = {
            'banco': ['bancco', 'banko', 'bango'],
            'seguridad': ['seguirdad', 'seguriad', 'seguridda'],
            'cuenta': ['cuenta', 'cuanta', 'cuentta'],
            'verificar': ['berificar', 'verificar', 'berifficar'],
            'paypal': ['payp4l', 'payp@l', 'paypaI'],
            'amazon': ['amaz0n', 'amazom', 'amazoon'],
            'google': ['g00gle', 'googIe', 'go0gle']
        }

    def analyze_text(self, text: str, html: str = "", subject: str = "") -> TextAnalysis:
        """Analiza el texto completo del email"""
        
        # Combinar todo el texto para análisis
        full_text = f"{subject} {text} {self._extract_text_from_html(html)}"
        
        # Análisis de ortografía
        spelling_errors = self._count_spelling_errors(full_text)
        
        # Análisis de gramática
        grammar_score = self._analyze_grammar(full_text)
        
        # Detectar palabras clave de urgencia
        urgency_keywords = self._detect_urgency_keywords(full_text)
        
        # Detectar frases sospechosas
        suspicious_phrases = self._detect_suspicious_phrases(full_text)
        
        # Verificar consistencia del idioma
        language_consistency = self._check_language_consistency(full_text)
        
        return TextAnalysis(
            spelling_errors=spelling_errors,
            grammar_score=grammar_score,
            urgency_keywords=urgency_keywords,
            suspicious_phrases=suspicious_phrases,
            language_consistency=language_consistency
        )

    def _extract_text_from_html(self, html: str) -> str:
        """Extrae texto limpio del HTML"""
        if not html:
            return ""
        
        # Remover tags HTML básicos
        clean_text = re.sub(r'<[^>]+>', ' ', html)
        # Decodificar entidades HTML
        clean_text = clean_text.replace('&nbsp;', ' ')
        clean_text = clean_text.replace('&amp;', '&')
        clean_text = clean_text.replace('&lt;', '<')
        clean_text = clean_text.replace('&gt;', '>')
        
        return clean_text

    def _count_spelling_errors(self, text: str) -> int:
        """Cuenta errores ortográficos obvios"""
        errors = 0
        text_lower = text.lower()
        
        # Buscar errores comunes conocidos
        for correct, misspellings in self.common_misspellings.items():
            for misspelling in misspellings:
                errors += len(re.findall(r'\b' + re.escape(misspelling) + r'\b', text_lower))
        
        # Detectar repetición excesiva de caracteres (ej: "hoooola")
        excessive_repeats = re.findall(r'\b\w*([a-z])\1{3,}\w*\b', text_lower)
        errors += len(excessive_repeats)
        
        # Detectar números mezclados con letras de forma sospechosa
        suspicious_alphanumeric = re.findall(r'\b[a-z]+\d+[a-z]+\b|\b\d+[a-z]+\d+\b', text_lower)
        errors += len(suspicious_alphanumeric)
        
        return errors

    def _analyze_grammar(self, text: str) -> float:
        """Analiza la gramática del texto (score de 0 a 1)"""
        try:
            blob = TextBlob(text)
            sentences = blob.sentences
            
            if not sentences:
                return 0.5  # Neutral si no hay texto
            
            # Factores que afectan el score de gramática
            score = 1.0
            
            # Penalizar por falta de puntuación
            if not re.search(r'[.!?]', text):
                score -= 0.3
            
            # Penalizar por uso excesivo de mayúsculas
            uppercase_ratio = sum(1 for c in text if c.isupper()) / len(text) if text else 0
            if uppercase_ratio > 0.3:
                score -= 0.2
            
            # Penalizar por espaciado inconsistente
            if re.search(r'\s{3,}', text) or re.search(r'\w\s\w\s\w', text):
                score -= 0.2
            
            return max(0.0, min(1.0, score))
            
        except Exception:
            return 0.5

    def _detect_urgency_keywords(self, text: str) -> List[str]:
        """Detecta palabras clave que indican urgencia"""
        text_lower = text.lower()
        found_keywords = []
        
        for lang, keywords in self.urgency_keywords.items():
            for keyword in keywords:
                if keyword in text_lower:
                    found_keywords.append(keyword)
        
        return found_keywords

    def _detect_suspicious_phrases(self, text: str) -> List[str]:
        """Detecta frases comúnmente usadas en phishing"""
        text_lower = text.lower()
        found_phrases = []
        
        for phrase in self.suspicious_phrases:
            if phrase in text_lower:
                found_phrases.append(phrase)
        
        return found_phrases

    def _check_language_consistency(self, text: str) -> bool:
        """Verifica si el idioma es consistente en todo el texto"""
        try:
            blob = TextBlob(text)
            detected_lang = blob.detect_language()
            
            # Para textos muy cortos, asumimos consistencia
            if len(text.split()) < 10:
                return True
            
            # Detectar mezcla sospechosa de idiomas
            spanish_words = sum(1 for word in text.split() if self._is_spanish_word(word))
            english_words = sum(1 for word in text.split() if self._is_english_word(word))
            total_words = len(text.split())
            
            if total_words == 0:
                return True
            
            # Si hay más del 30% de cada idioma, podría ser inconsistente
            spanish_ratio = spanish_words / total_words
            english_ratio = english_words / total_words
            
            return not (spanish_ratio > 0.3 and english_ratio > 0.3)
            
        except Exception:
            return True  # En caso de error, asumimos consistencia

    def _is_spanish_word(self, word: str) -> bool:
        """Verifica si una palabra es probablemente española"""
        spanish_indicators = ['ñ', 'á', 'é', 'í', 'ó', 'ú', 'ü']
        spanish_endings = ['ción', 'dad', 'mente', 'ando', 'endo']
        
        word_lower = word.lower()
        
        # Buscar caracteres específicos del español
        if any(char in word_lower for char in spanish_indicators):
            return True
        
        # Buscar terminaciones típicas del español
        if any(word_lower.endswith(ending) for ending in spanish_endings):
            return True
        
        return False

    def _is_english_word(self, word: str) -> bool:
        """Verifica si una palabra es probablemente inglesa"""
        english_patterns = ['ing', 'tion', 'ed', 'ly', 'er', 'est']
        english_words = ['the', 'and', 'you', 'your', 'click', 'here', 'verify']
        
        word_lower = word.lower()
        
        # Palabras comunes en inglés
        if word_lower in english_words:
            return True
        
        # Patrones típicos del inglés
        if any(word_lower.endswith(pattern) for pattern in english_patterns):
            return True
        
        return False