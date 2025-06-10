import re
import requests
import socket
from urllib.parse import urlparse, unquote
from typing import List, Dict, Set, Optional
import tldextract
from app.models.detection_models import URLAnalysis

class URLAnalyzer:
    def __init__(self):
        # Dominios legítimos conocidos
        self.legitimate_domains = {
            'banks': [
                'bancolombia.com', 'bancodebogota.com', 'davivienda.com',
                'bancopopular.com.co', 'bbva.com.co', 'bancoagrario.gov.co',
                'colpatria.com', 'bancocajasocial.com'
            ],
            'tech': [
                'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
                'paypal.com', 'facebook.com', 'instagram.com', 'twitter.com',
                'linkedin.com', 'youtube.com', 'netflix.com'
            ],
            'government': [
                'gov.co', 'dian.gov.co', 'mintic.gov.co', 'presidencia.gov.co',
                'policia.gov.co', 'ejercito.mil.co'
            ]
        }
        
        # Servicios de acortamiento de URLs
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'short.link', 'ow.ly', 't.co',
            'goo.gl', 'tiny.cc', 'is.gd', 'buff.ly', 'rebrand.ly'
        ]
        
        # Patrones sospechosos en URLs
        self.suspicious_patterns = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
            r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.',  # Subdominios sospechosos
            r'(secure|security|verification|update|confirm).*[0-9]+',
            r'[a-z]+[0-9]+[a-z]+\.',  # Mezcla aleatoria de letras y números
            r'[a-z]{20,}',  # Dominios muy largos
            r'(phishing|malware|suspicious)',  # Palabras obviamente maliciosas
        ]
        
        # Dominios comúnmente imitados
        self.commonly_spoofed = {
            'paypal': ['payp4l', 'paypaI', 'paypaII', 'paypaul', 'paypal1'],
            'amazon': ['amaz0n', 'amazom', 'amazoon', 'amnazon'],
            'google': ['g00gle', 'googIe', 'go0gle', 'gooogle'],
            'microsoft': ['microsft', 'micr0soft', 'microsooft'],
            'apple': ['appIe', 'appl3', 'aple', 'applle'],
            'bancolombia': ['bancol0mbia', 'bancolomb1a', 'bancolombia1']
        }

    def extract_urls(self, text: str, html: str = "") -> List[str]:
        """Extrae todas las URLs del texto y HTML"""
        urls = set()
        
        # Patrones para encontrar URLs
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[/\w\-._~:/?#[\]@!$&\'()*+,;=]*'
        
        # Extraer URLs del texto plano
        text_urls = re.findall(url_pattern, text)
        urls.update(text_urls)
        
        # Extraer URLs del HTML
        if html:
            # Enlaces href
            href_pattern = r'href=["\']([^"\']+)["\']'
            href_urls = re.findall(href_pattern, html, re.IGNORECASE)
            urls.update(href_urls)
            
            # URLs en src de imágenes
            src_pattern = r'src=["\']([^"\']+)["\']'
            src_urls = re.findall(src_pattern, html, re.IGNORECASE)
            urls.update(src_urls)
        
        # Limpiar y filtrar URLs
        cleaned_urls = []
        for url in urls:
            cleaned_url = self._clean_url(url)
            if cleaned_url and self._is_valid_url(cleaned_url):
                cleaned_urls.append(cleaned_url)
        
        return cleaned_urls

    def analyze_urls(self, urls: List[str]) -> List[URLAnalysis]:
        """Analiza una lista de URLs en busca de indicadores de phishing"""
        results = []
        
        for url in urls:
            analysis = self._analyze_single_url(url)
            results.append(analysis)
        
        return results

    def _analyze_single_url(self, url: str) -> URLAnalysis:
        """Analiza una URL individual"""
        reasons = []
        is_suspicious = False
        is_shortened = False
        redirects_to = None
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Verificar si es un acortador de URLs
            extracted = tldextract.extract(url)
            if f"{extracted.domain}.{extracted.suffix}" in self.url_shorteners:
                is_shortened = True
                reasons.append("URL acortada")
                # Intentar seguir redirección
                redirects_to = self._follow_redirect(url)
                if redirects_to:
                    # Analizar la URL de destino recursivamente
                    redirect_analysis = self._analyze_single_url(redirects_to)
                    if redirect_analysis.is_suspicious:
                        is_suspicious = True
                        reasons.extend(redirect_analysis.reasons)
            
            # Verificar patrones sospechosos
            suspicious_patterns = self._check_suspicious_patterns(url)
            if suspicious_patterns:
                is_suspicious = True
                reasons.extend(suspicious_patterns)
            
            # Verificar si es imitación de dominio legítimo
            spoofing_check = self._check_domain_spoofing(domain)
            if spoofing_check:
                is_suspicious = True
                reasons.append(f"Posible imitación de: {spoofing_check}")
            
            # Verificar uso de IP en lugar de dominio
            if self._is_ip_address(domain):
                is_suspicious = True
                reasons.append("Uso de dirección IP en lugar de dominio")
            
            # Verificar subdominio sospechoso
            subdomain_check = self._check_suspicious_subdomain(domain)
            if subdomain_check:
                is_suspicious = True
                reasons.append(subdomain_check)
            
            # Verificar protocolo
            if parsed.scheme == 'http' and self._should_be_https(domain):
                reasons.append("Sitio que debería usar HTTPS usando HTTP")
            
            # Verificar longitud excesiva
            if len(url) > 200:
                is_suspicious = True
                reasons.append("URL excesivamente larga")
            
            # Verificar caracteres sospechosos
            if self._has_suspicious_characters(url):
                is_suspicious = True
                reasons.append("Contiene caracteres sospechosos")
            
        except Exception as e:
            is_suspicious = True
            reasons.append(f"Error al analizar URL: {str(e)}")
        
        return URLAnalysis(
            url=url,
            is_suspicious=is_suspicious,
            reasons=reasons,
            is_shortened=is_shortened,
            redirects_to=redirects_to
        )

    def _clean_url(self, url: str) -> str:
        """Limpia y normaliza una URL"""
        url = url.strip()
        
        # Agregar protocolo si falta
        if not url.startswith(('http://', 'https://')):
            if url.startswith('www.'):
                url = 'https://' + url
            elif '.' in url and not url.startswith('//'):
                url = 'https://' + url
        
        # Decodificar URL encoding
        url = unquote(url)
        
        return url

    def _is_valid_url(self, url: str) -> bool:
        """Verifica si la URL tiene formato válido"""
        try:
            parsed = urlparse(url)
            return bool(parsed.netloc and parsed.scheme in ['http', 'https'])
        except:
            return False

    def _check_suspicious_patterns(self, url: str) -> List[str]:
        """Verifica patrones sospechosos en la URL"""
        suspicious_found = []
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                if '[0-9]{1,3}' in pattern:  # IP pattern
                    suspicious_found.append("Contiene dirección IP")
                elif 'secure' in pattern:
                    suspicious_found.append("Patrón sospechoso relacionado con seguridad")
                elif '[a-z]+[0-9]+[a-z]+' in pattern:
                    suspicious_found.append("Mezcla sospechosa de letras y números")
                elif '[a-z]{20,}' in pattern:
                    suspicious_found.append("Dominio excesivamente largo")
                else:
                    suspicious_found.append("Patrón sospechoso detectado")
        
        return suspicious_found

    def _check_domain_spoofing(self, domain: str) -> Optional[str]:
        """Verifica si el dominio es una imitación de uno legítimo"""
        extracted = tldextract.extract(domain)
        domain_part = extracted.domain.lower()
        
        for legitimate, spoofs in self.commonly_spoofed.items():
            if domain_part in spoofs:
                return legitimate
            
            # Verificar similitud con dominios legítimos
            if self._is_similar_domain(domain_part, legitimate):
                return legitimate
        
        return None

    def _is_similar_domain(self, domain: str, legitimate: str) -> bool:
        """Verifica similitud entre dominios usando distancia de edición simple"""
        if len(domain) < 3 or len(legitimate) < 3:
            return False
        
        # Verificar substituciones comunes
        common_subs = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's'}
        normalized_domain = domain
        for digit, letter in common_subs.items():
            normalized_domain = normalized_domain.replace(digit, letter)
        
        # Verificar si es muy similar después de normalizaciones
        if normalized_domain == legitimate:
            return True
        
        # Verificar diferencias mínimas
        differences = sum(1 for a, b in zip(normalized_domain, legitimate) if a != b)
        if len(normalized_domain) == len(legitimate) and differences <= 2:
            return True
        
        return False

    def _is_ip_address(self, domain: str) -> bool:
        """Verifica si el dominio es una dirección IP"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, domain))

    def _check_suspicious_subdomain(self, domain: str) -> Optional[str]:
        """Verifica si el subdominio es sospechoso"""
        parts = domain.split('.')
        if len(parts) < 3:
            return None
        
        subdomain = parts[0]
        
        # Subdominios sospechosos comunes
        suspicious_subs = [
            'secure', 'security', 'verification', 'update', 'confirm',
            'login', 'account', 'banking', 'support', 'help', 'service',
            'authenticate', 'validate', 'check', 'verify'
        ]
        
        if subdomain in suspicious_subs:
            return f"Subdominio sospechoso: {subdomain}"
        
        # Verificar patrones como security123, update-now, etc.
        if re.match(r'^(secure|security|verify|update|confirm).*[0-9-]+$', subdomain):
            return f"Patrón de subdominio sospechoso: {subdomain}"
        
        return None

    def _should_be_https(self, domain: str) -> bool:
        """Verifica si un dominio debería usar HTTPS"""
        # Dominios que siempre deberían usar HTTPS
        https_domains = []
        
        # Agregar todos los dominios legítimos
        for category in self.legitimate_domains.values():
            https_domains.extend(category)
        
        return any(legit_domain in domain for legit_domain in https_domains)

    def _has_suspicious_characters(self, url: str) -> bool:
        """Verifica caracteres sospechosos en la URL"""
        # Caracteres que pueden usarse para confundir
        suspicious_chars = ['ℂ', 'ℍ', 'ℕ', 'ℙ', 'ℚ', 'ℝ', 'ℤ', 'ℎ', 'ℓ']  # Caracteres Unicode similares
        punycode_pattern = r'xn--'  # Dominios IDN/Punycode
        
        # Verificar caracteres Unicode sospechosos
        if any(char in url for char in suspicious_chars):
            return True
        
        # Verificar uso de Punycode (puede usarse para ataques homográficos)
        if punycode_pattern in url:
            return True
        
        # Verificar mezcla excesiva de guiones y números
        if re.search(r'-.*-.*-.*-', url):
            return True
        
        return False

    def _follow_redirect(self, url: str) -> Optional[str]:
        """Sigue una redirección para obtener la URL final"""
        try:
            response = requests.head(url, allow_redirects=True, timeout=5)
            return response.url if response.url != url else None
        except:
            return None