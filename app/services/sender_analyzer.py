import re
import socket
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from app.models.detection_models import SenderAnalysis
from app.models.email_models import EmailAddress, EmailHeaders

class SenderAnalyzer:
    def __init__(self):
        # Dominios con buena reputación
        self.trusted_domains = {
            'banks': [
                'bancolombia.com', 'bancodebogota.com', 'davivienda.com',
                'bancopopular.com.co', 'bbva.com.co', 'bancoagrario.gov.co'
            ],
            'tech': [
                'gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com',
                'google.com', 'microsoft.com', 'apple.com', 'amazon.com'
            ],
            'government': [
                'gov.co', 'dian.gov.co', 'policia.gov.co', 'mintic.gov.co'
            ],
            'legitimate_services': [
                'paypal.com', 'netflix.com', 'spotify.com', 'uber.com',
                'mercadolibre.com.co', 'computrabajo.com'
            ]
        }
        
        # Dominios sospechosos o conocidos por phishing
        self.suspicious_domains = [
            'tempmail.org', '10minutemail.com', 'guerrillamail.com',
            'mailinator.com', 'yopmail.com', 'throwaway.email',
            # Imitaciones comunes
            'payp4l.com', 'amaz0n.com', 'g00gle.com', 'microsft.com'
        ]
        
        # Patrones de nombres sospechosos
        self.suspicious_name_patterns = [
            r'[A-Z][a-z]+ [A-Z][a-z]+',  # Nombres muy genéricos
            r'(Security|Support|Service|Admin|No.?Reply)',  # Nombres típicos de phishing
            r'[A-Za-z0-9]{20,}',  # Nombres excesivamente largos o aleatorios
            r'^[A-Z\s]+$',  # Todo en mayúsculas
        ]

    def analyze_sender(self, sender: EmailAddress, headers: EmailHeaders) -> SenderAnalysis:
        """Analiza el remitente y headers para detectar spoofing"""
        
        # Extraer dominio del remitente
        sender_domain = self._extract_domain(sender.address)
        
        # Verificar reputación del dominio
        domain_reputation = self._check_domain_reputation(sender_domain)
        
        # Verificar si el remitente está siendo suplantado
        is_spoofed = self._check_spoofing(sender, headers)
        
        # Verificar autenticación SPF
        spf_pass = self._check_spf(headers)
        
        # Verificar autenticación DKIM
        dkim_pass = self._check_dkim(headers)
        
        # Verificar autenticación DMARC
        dmarc_pass = self._check_dmarc(headers)
        
        # Verificar consistencia del remitente
        sender_consistency = self._check_sender_consistency(sender, headers)
        
        return SenderAnalysis(
            is_spoofed=is_spoofed,
            domain_reputation=domain_reputation,
            spf_pass=spf_pass,
            dkim_pass=dkim_pass,
            dmarc_pass=dmarc_pass,
            sender_consistency=sender_consistency
        )

    def _extract_domain(self, email: str) -> str:
        """Extrae el dominio de una dirección de email"""
        try:
            return email.split('@')[1].lower()
        except (IndexError, AttributeError):
            return ""

    def _check_domain_reputation(self, domain: str) -> str:
        """Verifica la reputación del dominio"""
        if not domain:
            return "unknown"
        
        # Verificar si está en dominios confiables
        for category, domains in self.trusted_domains.items():
            if domain in domains or any(domain.endswith('.' + trusted) for trusted in domains):
                return "good"
        
        # Verificar si está en dominios sospechosos
        if domain in self.suspicious_domains:
            return "malicious"
        
        # Verificar patrones sospechosos en el dominio
        if self._has_suspicious_domain_pattern(domain):
            return "suspicious"
        
        # Verificar si es un dominio temporal o desechable
        if self._is_disposable_email_domain(domain):
            return "suspicious"
        
        return "unknown"

    def _has_suspicious_domain_pattern(self, domain: str) -> bool:
        """Verifica patrones sospechosos en el dominio"""
        # Dominios muy largos
        if len(domain) > 50:
            return True
        
        # Muchos números en el dominio
        if len(re.findall(r'\d', domain)) / len(domain) > 0.3:
            return True
        
        # Muchos guiones
        if domain.count('-') > 3:
            return True
        
        # Extensiones sospechosas
        suspicious_tlds = ['.tk', '.ml', '.cf', '.ga', '.top', '.click']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True
        
        # Imitaciones de dominios conocidos
        legitimate_domains = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'bancolombia']
        for legit in legitimate_domains:
            if legit in domain and domain != f"{legit}.com":
                # Verificar si es una imitación
                if self._is_domain_imitation(domain, legit):
                    return True
        
        return False

    def _is_domain_imitation(self, domain: str, legitimate: str) -> bool:
        """Verifica si un dominio es imitación de uno legítimo"""
        # Substituciones comunes
        domain_clean = domain.replace('-', '').replace('0', 'o').replace('1', 'l')
        
        if legitimate in domain_clean and domain != f"{legitimate}.com":
            return True
        
        # Verificar si agrega caracteres extra
        if domain.startswith(legitimate) and len(domain) > len(legitimate) + 4:
            return True
        
        return False

    def _is_disposable_email_domain(self, domain: str) -> bool:
        """Verifica si es un dominio de email temporal/desechable"""
        disposable_indicators = [
            'temp', 'temporary', '10min', 'disposable', 'throwaway',
            'guerrilla', 'mailinator', 'yopmail', 'minute'
        ]
        
        return any(indicator in domain for indicator in disposable_indicators)

    def _check_spoofing(self, sender: EmailAddress, headers: EmailHeaders) -> bool:
        """Verifica indicadores de spoofing del remitente"""
        spoofing_indicators = 0
        
        # Verificar consistencia entre From y Return-Path
        if headers.return_path:
            return_domain = self._extract_domain(headers.return_path.strip('<>'))
            sender_domain = self._extract_domain(sender.address)
            if return_domain and sender_domain and return_domain != sender_domain:
                spoofing_indicators += 1
        
        # Verificar el nombre del remitente
        if sender.name:
            if self._has_suspicious_sender_name(sender.name):
                spoofing_indicators += 1
        
        # Verificar headers Received para inconsistencias
        if self._check_received_headers_inconsistency(headers):
            spoofing_indicators += 1
        
        # Verificar si el dominio del sender coincide con los headers
        if self._check_domain_header_mismatch(sender, headers):
            spoofing_indicators += 1
        
        return spoofing_indicators >= 2

    def _has_suspicious_sender_name(self, name: str) -> bool:
        """Verifica si el nombre del remitente es sospechoso"""
        # Nombres muy genéricos o sospechosos
        suspicious_names = [
            'security team', 'support team', 'admin', 'administrator',
            'no reply', 'noreply', 'notification', 'alert', 'service'
        ]
        
        name_lower = name.lower()
        
        # Verificar nombres conocidos sospechosos
        if any(suspicious in name_lower for suspicious in suspicious_names):
            return True
        
        # Verificar patrones sospechosos
        for pattern in self.suspicious_name_patterns:
            if re.match(pattern, name, re.IGNORECASE):
                return True
        
        # Nombre excesivamente largo
        if len(name) > 100:
            return True
        
        # Solo mayúsculas (puede indicar spam)
        if name.isupper() and len(name) > 10:
            return True
        
        return False

    def _check_received_headers_inconsistency(self, headers: EmailHeaders) -> bool:
        """Verifica inconsistencias en los headers Received"""
        if not headers.received:
            return False
        
        # Buscar saltos geográficos improbables
        # Buscar diferencias de tiempo sospechosas
        # Buscar servidores con nombres sospechosos
        
        for received in headers.received:
            if 'localhost' in received.lower():
                return True
            
            # Verificar IPs privadas en headers públicos
            private_ip_pattern = r'192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.'
            if re.search(private_ip_pattern, received):
                return True
        
        return False

    def _check_domain_header_mismatch(self, sender: EmailAddress, headers: EmailHeaders) -> bool:
        """Verifica discrepancias entre el dominio del sender y los headers"""
        sender_domain = self._extract_domain(sender.address)
        
        # Verificar Message-ID
        if headers.message_id:
            try:
                message_id_domain = headers.message_id.split('@')[1].strip('>')
                if message_id_domain != sender_domain:
                    return True
            except (IndexError, AttributeError):
                pass
        
        return False

    def _check_spf(self, headers: EmailHeaders) -> bool:
        """Verifica el resultado de autenticación SPF"""
        if not headers.received_spf:
            return False
        
        # Buscar resultado SPF en los headers
        spf_results = headers.received_spf.lower()
        return 'pass' in spf_results

    def _check_dkim(self, headers: EmailHeaders) -> bool:
        """Verifica el resultado de autenticación DKIM"""
        if not headers.dkim_signature:
            return False
        
        # Verificar en authentication_results
        if headers.authentication_results:
            for auth_result in headers.authentication_results:
                if 'dkim=pass' in auth_result.lower():
                    return True
        
        return False

    def _check_dmarc(self, headers: EmailHeaders) -> bool:
        """Verifica el resultado de autenticación DMARC"""
        if headers.authentication_results:
            for auth_result in headers.authentication_results:
                if 'dmarc=pass' in auth_result.lower():
                    return True
        
        return False

    def _check_sender_consistency(self, sender: EmailAddress, headers: EmailHeaders) -> bool:
        """Verifica la consistencia general del remitente"""
        consistency_score = 0
        total_checks = 0
        
        # Verificar consistencia de dominio
        sender_domain = self._extract_domain(sender.address)
        
        # Check 1: Consistencia con Return-Path
        total_checks += 1
        if headers.return_path:
            return_domain = self._extract_domain(headers.return_path.strip('<>'))
            if return_domain == sender_domain:
                consistency_score += 1
        
        # Check 2: Message-ID consistency
        total_checks += 1
        if headers.message_id:
            try:
                msg_id_domain = headers.message_id.split('@')[1].strip('>')
                if msg_id_domain == sender_domain:
                    consistency_score += 1
            except:
                pass
        
        # Check 3: Nombre del remitente apropiado
        total_checks += 1
        if sender.name and not self._has_suspicious_sender_name(sender.name):
            consistency_score += 1
        
        # Retornar True si al menos 2/3 de las verificaciones pasan
        return consistency_score >= (total_checks * 0.67) if total_checks > 0 else False