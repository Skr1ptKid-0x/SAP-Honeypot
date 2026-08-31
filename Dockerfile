FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./
COPY templates ./templates

RUN useradd --create-home appuser \
    && mkdir /data \
    && chown appuser:appuser /data

ENV SAP_HONEYPOT_DB_PATH=/data/honeypot.db

USER appuser

EXPOSE 8080

CMD ["python", "app.py"]
