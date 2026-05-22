
# DevSecOps Pipeline Project Memory

## Project Structure


## Technology Stack
- Frontend: React (built via node:18-alpine, served via nginx:alpine)
- Backend: Python Flask (python:3.10-slim)
- Container: Docker multi-stage builds
- CI/CD: GitHub Actions with:
  - TruffleHog (secret scanning)
  - Trivy (SCA + container scanning)
  - Semgrep (SAST)
  - Render deploy webhook
- Hosting: Render (free tier)

## Pipeline Flow
1. On push/PR to main → Trigger pipeline
2. Secret scanning (TruffleHog) - first gate
3. Dependency scanning (Trivy SCA) - runs after secrets pass
4. Static analysis (Semgrep) - runs after secrets pass
5. Container security (Trivy on built images) - runs after SCA/SAST pass
6. Deploy (Render webhook) - runs only if ALL checks pass

## Key Decisions
- Using node:18-alpine for React build stage
- Using nginx:alpine for serving static files
- Using python:3.10-slim for backend
- TruffleHog scans full git history (fetch-depth: 0)
- Trivy configured to fail on CRITICAL/HIGH vulnerabilities
- Semgrep uses auto config for broad rule coverage
