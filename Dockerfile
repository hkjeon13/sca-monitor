FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SCA_MONITOR_HOST=0.0.0.0 \
    SCA_MONITOR_PORT=18780 \
    SCA_MONITOR_FRONTEND_DIR=/app/frontend \
    SCA_MONITOR_AUTO_MIGRATE=false

WORKDIR /app
COPY pyproject.toml ./
COPY backend ./backend
COPY frontend ./frontend
COPY migrations ./migrations
COPY scripts ./scripts
RUN pip install --no-cache-dir .

USER 1000:1000
EXPOSE 18780
CMD ["python", "-m", "backend.sca_monitor"]
