# Multi-stage build optimizado para Railway
FROM python:3.11-slim as builder

# Instalar dependencias de build
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Crear directorio de trabajo
WORKDIR /app

# Copiar requirements y instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Descargar datos de NLTK
RUN python -c "import nltk; nltk.download('punkt', download_dir='/nltk_data'); nltk.download('stopwords', download_dir='/nltk_data')"

# Etapa final optimizada
FROM python:3.11-slim

# Instalar solo las dependencias runtime necesarias
RUN apt-get update && apt-get install -y \
    && rm -rf /var/lib/apt/lists/*

# Crear usuario no-root
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Establecer directorio de trabajo
WORKDIR /app

# Copiar dependencias instaladas desde builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /nltk_data /home/appuser/nltk_data

# Copiar código de la aplicación
COPY app/ ./app/

# Cambiar ownership
RUN chown -R appuser:appuser /app /home/appuser
USER appuser

# Variables de entorno optimizadas
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    NLTK_DATA=/home/appuser/nltk_data \
    PORT=8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')" || exit 1

# Exponer puerto
EXPOSE 8000

# Comando optimizado para Railway
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]