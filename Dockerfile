FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
CMD ["sh", "-c", "gunicorn app:app --workers 2 --threads 4 --timeout 45 --bind 0.0.0.0:${PORT:-8080}"]
