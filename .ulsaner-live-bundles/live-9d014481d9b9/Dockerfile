FROM python:3.11-slim
WORKDIR /app
COPY app/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ .
RUN useradd -m appuser
USER appuser
EXPOSE 8000
CMD ["python", "main.py"]
