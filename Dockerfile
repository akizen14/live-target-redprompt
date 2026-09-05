FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

# Platforms (Fly, Render, Railway, HF Spaces) inject PORT. 8080 is the fallback.
ENV PORT=8080
EXPOSE 8080
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT}"]
