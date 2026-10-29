FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY Pipeline/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY Dashboard/analysis/ Dashboard/analysis/
COPY Dashboard/project_paths.py Dashboard/project_paths.py
COPY AnomalyDetection/ AnomalyDetection/

ENTRYPOINT ["python", "-m", "Dashboard.analysis.pipeline", "--db", "/data/mits.db"]
