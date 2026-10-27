# AI-Assisted Security Event Detection Platform — Runbook

This guide explains how to start, operate, and stop the local development environment on Windows using PowerShell.

## 1. Prerequisites

- Windows with PowerShell
- Python environment managed by `uv`
- Docker Desktop running
- Valid AWS credentials with access to the Kinesis stream
- `.env` configured with the required application settings

Project directory:

```powershell
cd E:\Projects\ai-security-event-platform
```

## 2. Start Infrastructure

Start Prometheus and Grafana:

```powershell
docker compose -f compose.yaml up -d
```

Check container status:

```powershell
docker compose -f compose.yaml ps
```

Expected services include:

- Prometheus — `http://localhost:9090`
- Grafana — `http://localhost:3000`

**Current Grafana note:** Datasource provisioning has temporarily been disabled by renaming `monitoring/grafana/provisioning/datasources/prometheus.yml` to `prometheus.yml.bak`. Grafana may open without the provisioned Prometheus datasource, and dashboards may not display data. Leave the backup in place until the provisioning issue is fixed.

## 3. Start the Application

Open separate PowerShell terminals for the following processes. Run each command from the project root.

### Terminal 1 — FastAPI

```powershell
uv run uvicorn app.api.main:app --reload
```

Endpoints:

- Swagger UI: `http://localhost:8000/docs`
- API metrics: `http://localhost:8000/metrics`

### Terminal 2 — Kinesis Consumer

```powershell
uv run python -m app.consumer.main
```

The consumer continuously polls the configured AWS Kinesis stream, processes events, and persists checkpoints and detection results.

Consumer metrics:

- `http://localhost:9101/`

Keep this process running while generating events. Do not use `--once` for continuous processing.

### Terminal 3 — Synthetic Event Producer

Generate 100 synthetic security events:

```powershell
uv run python -m app.producer.main --count 100
```

Run this command whenever you want to generate another batch of events.

**Recommended order:** Start the consumer before running the producer.

### Terminal 4 — Optional AI Summary Worker

```powershell
uv run python -m app.summarization.worker --limit 10
```

This runs the summary worker against