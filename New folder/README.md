
# DevSecOps Secure Deployment Pipeline

A fully automated DevSecOps pipeline that integrates security scanning at every stage of the CI/CD process. Built with open-source tools and designed for free-tier hosting.

## 🏗️ Architecture



## 🚀 Pipeline Security Gates

### 1. Secret Scanning (TruffleHog)
- Scans full git history for accidentally committed secrets
- Detects API keys, passwords, tokens, and credentials
- Fails the pipeline if any secrets are found

### 2. Dependency Scanning (Trivy - SCA)
- Scans package.json and requirements.txt for vulnerable dependencies
- Fails on CRITICAL and HIGH severity vulnerabilities
- Ensures no known vulnerable packages are deployed

### 3. Static Analysis (Semgrep - SAST)
- Analyzes code for security vulnerabilities and logic flaws
- Uses automatically selected rules based on codebase
- Catches issues like XSS, injection flaws, insecure configurations

### 4. Container Security (Trivy)
- Builds Docker images in the pipeline
- Scans base OS images for deep-level vulnerabilities
- Only images passing security checks proceed to deployment

### 5. Auto-Deployment (Render)
- Triggered via webhook only if ALL security checks pass
- Deploys verified code to production automatically

## 📁 Project Structure



## 🛠️ Technologies Used

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Frontend | React + Nginx | User interface |
| Backend | Python Flask | REST API |
| Containerization | Docker | Consistent environments |
| CI/CD | GitHub Actions | Pipeline orchestration |
| Secret Scanning | TruffleHog | Credential detection |
| Dependency Scanning | Trivy | Vulnerability scanning |
| Static Analysis | Semgrep | Code security analysis |
| Container Scanning | Trivy | Image vulnerability scanning |
| Hosting | Render (Free Tier) | Deployment |

## 🚦 Getting Started

### Prerequisites
- Git
- Docker Desktop
- GitHub account
- Render account (for deployment)

### Local Development

1. **Clone the repository**
   

2. **Run the frontend**
   

3. **Run the backend**
   

4. **Build and run with Docker**
   

### GitHub Actions Setup

1. Push code to a GitHub repository
2. The pipeline runs automatically on push/PR to `main`
3. Monitor pipeline runs under the "Actions" tab

### Render Deployment Setup

1. Create a free Render account
2. Create a new Web Service
3. In Render dashboard, generate a Deploy Webhook URL
4. Add the webhook URL as a GitHub secret:
   - Go to Repository → Settings → Secrets and Variables → Actions
   - Add `RENDER_DEPLOY_WEBHOOK_URL` with the webhook URL

## 🔒 Security Best Practices

- **Never commit secrets**: All credentials are scanned before deployment
- **Dependency hygiene**: Only packages passing security scans are deployed
- **Container hardening**: Base images are scanned for vulnerabilities
- **Defense in depth**: Multiple security layers prevent single-point failures
- **Immutable deployments**: Each deployment is from a freshly verified build

## 📊 Pipeline Status Badges

Add these to your README to show pipeline status:



## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License.

## 🙏 Acknowledgments

- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [Trivy](https://github.com/aquasecurity/trivy)
- [Semgrep](https://github.com/semgrep/semgrep)
- [Render](https://render.com)
