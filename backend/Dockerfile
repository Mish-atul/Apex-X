# APEX-X backend (FastAPI) - build context: repository root
#   docker build -f backend/Dockerfile -t apex-x-backend .
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 \
    APEX_DATA_DIR=/app/data     DATABASE_URL=sqlite:////app/data/apex_x.db     ADB_SERVER_SOCKET=tcp:host.docker.internal:5037     HOME=/home/apex \
    PATH="/opt/tools/bin:/opt/platform-tools:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
        openjdk-17-jre-headless unzip curl git ca-certificates \
        build-essential pkg-config libssl-dev libmagic1 libffi-dev \
    && curl -fsSL -o /tmp/pt.zip https://dl.google.com/android/repository/platform-tools-latest-linux.zip \
    && unzip -q /tmp/pt.zip -d /opt && rm /tmp/pt.zip \
    && rm -rf /var/lib/apt/lists/*

# Static analysis tools; exposed on PATH so shutil.which("apktool"/"jadx") finds them
COPY tools/apktool.jar /opt/tools/apktool.jar
COPY tools/jadx /opt/tools/jadx
RUN mkdir -p /opt/tools/bin \
    && printf '#!/bin/sh\nexec java -jar /opt/tools/apktool.jar "$@"\n' > /opt/tools/bin/apktool \
    && sed -i 's/\r$//' /opt/tools/jadx/bin/jadx \
    && chmod +x /opt/tools/bin/apktool /opt/tools/jadx/bin/jadx \
    && ln -s /opt/tools/jadx/bin/jadx /opt/tools/bin/jadx

WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

RUN useradd --create-home --uid 1000 apex
COPY --chown=apex:apex backend/ .
RUN mkdir -p /app/data && chown -R apex:apex /app

USER apex
# Bake Quark rules into the image (stored under ~/.quark-engine)
RUN freshquark

VOLUME ["/app/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3     CMD curl -fsS http://localhost:8080/docs >/dev/null || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
