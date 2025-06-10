from pydantic import BaseModel, EmailStr, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime

class EmailAddress(BaseModel):
    address: str
    name: Optional[str] = ""

class EmailHeaders(BaseModel):
    received: Optional[List[str]] = []
    return_path: Optional[str] = None
    authentication_results: Optional[List[str]] = []
    dkim_signature: Optional[str] = None
    spf: Optional[str] = None
    dmarc: Optional[str] = None
    message_id: Optional[str] = None
    x_sender: Optional[str] = None
    
    # Campos adicionales para análisis
    x_received: Optional[List[str]] = []
    x_originating_ip: Optional[str] = None
    received_spf: Optional[str] = None

class EmailData(BaseModel):
    date: datetime
    subject: str
    text: str
    html: str
    sender: EmailAddress = Field(alias="from")
    to: List[EmailAddress]
    cc: Optional[List[EmailAddress]] = []
    bcc: Optional[List[EmailAddress]] = []
    attachments: Optional[List[Dict[str, Any]]] = []
    headers: EmailHeaders
    
    @validator('text', 'html', 'subject')
    def clean_content(cls, v):
        """Limpia y valida el contenido del email"""
        if v is None:
            return ""
        return str(v).strip()
    
    @validator('sender', pre=True)
    def validate_sender(cls, v):
        """Valida el remitente"""
        if isinstance(v, dict):
            return EmailAddress(**v)
        return v

class EmailBatch(BaseModel):
    """Para procesar múltiples emails"""
    emails: List[EmailData]
    
    @validator('emails')
    def validate_email_list(cls, v):
        if len(v) == 0:
            raise ValueError("Al menos un email debe ser proporcionado")
        if len(v) > 50:  # Límite de procesamiento
            raise ValueError("Máximo 50 emails por batch")
        return v