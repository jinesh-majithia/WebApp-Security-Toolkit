
"""
Comprehensive Test Script for DevSecOps Pipeline Application
============================================================
Tests both the Flask backend API and the React frontend endpoints.

Usage:
    # Ensure backend server is running (python backend/app.py)
    python tests/test_app.py

    # Or run specific test categories:
    python tests/test_app.py --backend-only
    python tests/test_app.py --frontend-only
    python tests/test_app.py --verbose

Requirements:
    pip install requests
"""

import sys
import json
import argparse
import time
from pathlib import Path

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' library not found. Install it with: pip install requests")
    sys.exit(1)

# Configuration
BACKEND_URL = "http://localhost:5000"
FRONTEND_URL = "http://localhost:3000"
TIMEOUT = 5  # seconds

# ASCII status indicators
PASS_SYMBOL = "[PASS]"
FAIL_SYMBOL = "[FAIL]"
WARN_SYMBOL = "[WARN]"

passed = 0
failed = 0
warnings = 0


def print_header(text):
    """Print a formatted section header."""
    print()
    print("=" * 60)
    print(f"  {text}")
    print("=" * 60)
    print()


def print_result(test_name, status, detail=""):
    """Print a test result with status symbol."""
    global passed, failed, warnings
    if status == "PASS":
        passed += 1
        symbol = PASS_SYMBOL
    elif status == "FAIL":
        failed += 1
        symbol = FAIL_SYMBOL
    else:  # WARN
        warnings += 1
        symbol = WARN_SYMBOL

    detail_str = f" -- {detail}" if detail else ""
    print(f"  {symbol} {test_name}{detail_str}")


def test_backend_root():
    """Test the backend root endpoint returns expected JSON."""
    try:
        resp = requests.get(f"{BACKEND_URL}/", timeout=TIMEOUT)
        data = resp.json()
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert data["service"] == "DevSecOps Backend API"
        assert data["status"] == "healthy"
        assert data["version"] == "1.0.0"
        print_result("GET / -- Root endpoint", "PASS", "Returns correct service info")
        return True
    except requests.exceptions.ConnectionError:
        print_result("GET / -- Root endpoint", "FAIL", "Connection refused -- is the backend running?")
        return False
    except Exception as e:
        print_result("GET / -- Root endpoint", "FAIL", str(e))
        return False


def test_backend_health():
    """Test the health endpoint."""
    try:
        resp = requests.get(f"{BACKEND_URL}/health", timeout=TIMEOUT)
        data = resp.json()
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert data["status"] == "ok"
        print_result("GET /health -- Health check", "PASS", "Service is healthy")
        return True
    except Exception as e:
        print_result("GET /health -- Health check", "FAIL", str(e))
        return False


def test_backend_pipeline():
    """Test the pipeline status endpoint."""
    try:
        resp = requests.get(f"{BACKEND_URL}/api/pipeline", timeout=TIMEOUT)
        data = resp.json()
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert data["pipeline"] == "DevSecOps Secure Deployment Pipeline"
        gates = data["security_gates"]
        assert len(gates) == 4, f"Expected 4 security gates, got {len(gates)}"

        expected_gates = [
            {"name": "Secret Scanning", "tool": "TruffleHog", "status": "pass"},
            {"name": "Dependency Scanning", "tool": "Trivy", "status": "pass"},
            {"name": "Static Analysis", "tool": "Semgrep", "status": "pass"},
            {"name": "Container Security", "tool": "Trivy", "status": "pass"},
        ]

        for i, gate in enumerate(gates):
            expected = expected_gates[i]
            for key in ["name", "tool", "status"]:
                assert gate[key] == expected[key], f"Gate {i}: expected {key}={expected[key]}, got {gate[key]}"

        print_result("GET /api/pipeline -- Pipeline status", "PASS", "All 4 security gates present and passing")
        return True
    except Exception as e:
        print_result("GET /api/pipeline -- Pipeline status", "FAIL", str(e))
        return False


def test_backend_invalid_route():
    """Test that invalid routes return 404."""
    try:
        resp = requests.get(f"{BACKEND_URL}/nonexistent", timeout=TIMEOUT)
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}"
        print_result("GET /nonexistent -- 404 handling", "PASS", "Returns 404 for unknown routes")
        return True
    except Exception as e:
        print_result("GET /nonexistent -- 404 handling", "FAIL", str(e))
        return False


def test_backend_response_time():
    """Test that backend responds within acceptable time."""
    try:
        # Warm up: make a request first to avoid cold-start penalty
        requests.get(f"{BACKEND_URL}/", timeout=TIMEOUT)
        start = time.time()
        requests.get(f"{BACKEND_URL}/", timeout=TIMEOUT)
        elapsed = time.time() - start
        ms = int(elapsed * 1000)
        if elapsed < 1.0:
            print_result("Response time -- Root endpoint", "PASS", f"{ms}ms")
        elif elapsed < 3.0:
            print_result("Response time -- Root endpoint", "WARN", f"{ms}ms (acceptable but slow)")
        else:
            print_result("Response time -- Root endpoint", "FAIL", f"{ms}ms (too slow)")
        return True
    except Exception as e:
        print_result("Response time -- Root endpoint", "FAIL", str(e))
        return False


def test_backend_headers():
    """Test that backend returns proper headers."""
    try:
        resp = requests.get(f"{BACKEND_URL}/", timeout=TIMEOUT)
        ct = resp.headers.get("Content-Type", "")
        assert "application/json" in ct, f"Expected application/json, got {ct}"
        print_result("Headers -- Content-Type", "PASS", "application/json")
        return True
    except Exception as e:
        print_result("Headers -- Content-Type", "FAIL", str(e))
        return False


def test_frontend_accessible():
    """Test that the frontend is serving HTML."""
    try:
        resp = requests.get(FRONTEND_URL, timeout=TIMEOUT)
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        html = resp.text
        assert "<!DOCTYPE html>" in html or "<html" in html, "Response is not HTML"
        assert "DevSecOps Pipeline Demo" in html
        assert "id=\"root\"" in html or "root" in html.lower()
        print_result("GET / -- Frontend serving", "PASS", "React app is accessible")
        return True
    except requests.exceptions.ConnectionError:
        print_result("GET / -- Frontend serving", "FAIL", "Connection refused -- is the frontend running?")
        return False
    except Exception as e:
        print_result("GET / -- Frontend serving", "FAIL", str(e))
        return False


def test_frontend_spa_shell():
    """Test that the React SPA shell is served correctly (React renders content client-side)."""
    try:
        resp = requests.get(FRONTEND_URL, timeout=TIMEOUT)
        html = resp.text
        checks = {
            "React root mount point": 'id="root"',
            "Page title in HTML": "DevSecOps Pipeline Demo",
            "React/JS bundle reference": "/static/js/",
            "Favicon reference": "favicon",
            "Manifest reference": "manifest",
        }
        all_ok = True
        for name, pattern in checks.items():
            if pattern in html:
                print_result(f"Frontend SPA shell -- {name}", "PASS")
            else:
                print_result(f"Frontend SPA shell -- {name}", "WARN", f"'{pattern}' not found (may be optional)")
                all_ok = False
        return all_ok
    except Exception as e:
        print_result("Frontend SPA shell check", "FAIL", str(e))
        return False


def test_dockerfile_frontend():
    """Verify frontend Dockerfile exists and has multi-stage build."""
    dockerfile_path = Path("frontend/Dockerfile")
    if not dockerfile_path.exists():
        print_result("Frontend Dockerfile exists", "FAIL", "File not found")
        return False

    content = dockerfile_path.read_text()

    checks = {
        "FROM node:18-alpine AS build": "Build stage with Node",
        "FROM nginx:alpine": "Serving stage with Nginx",
        "COPY --from=build": "Multi-stage copy",
        "EXPOSE 80": "Port 80 exposed",
        "npm run build": "Build command",
    }

    all_ok = True
    for fragment, label in checks.items():
        if fragment in content:
            print_result(f"Frontend Dockerfile -- {label}", "PASS")
        else:
            print_result(f"Frontend Dockerfile -- {label}", "FAIL", f"'{fragment}' not found")
            all_ok = False
    return all_ok


def test_dockerfile_backend():
    """Verify backend Dockerfile exists and has proper config."""
    dockerfile_path = Path("backend/Dockerfile")
    if not dockerfile_path.exists():
        print_result("Backend Dockerfile exists", "FAIL", "File not found")
        return False

    content = dockerfile_path.read_text()

    checks = {
        "FROM python:3.10-slim": "Python base image",
        "gunicorn": "Uses Gunicorn (not Flask dev server)",
        "EXPOSE 5000": "Port 5000 exposed",
        "requirements.txt": "Installs from requirements",
    }

    all_ok = True
    for fragment, label in checks.items():
        if fragment in content:
            print_result(f"Backend Dockerfile -- {label}", "PASS")
        else:
            print_result(f"Backend Dockerfile -- {label}", "FAIL", f"'{fragment}' not found")
            all_ok = False
    return all_ok


def test_workflow_file():
    """Verify GitHub Actions workflow file exists and has all jobs."""
    workflow_path = Path(".github/workflows/devsecops-pipeline.yml")
    if not workflow_path.exists():
        print_result("GitHub Actions workflow exists", "FAIL", "File not found")
        return False

    content = workflow_path.read_text()

    checks = {
        "Secret scanning job": "secret-scanning",
        "Secret scanning with TruffleHog": "trufflesecurity/trufflehog",
        "Dependency scanning job": "dependency-scanning",
        "Dependency scanning with Trivy": "aquasecurity/trivy-action",
        "Static analysis job": "static-analysis",
        "Static analysis with Semgrep": "semgrep",
        "Container security job": "container-security",
        "Docker build step": "docker build",
        "Container image scanning with Trivy": "aquasecurity/trivy-action",
        "Deploy job": "deploy",
        "Deploy via webhook": "RENDER_DEPLOY_WEBHOOK_URL",
        "Job dependencies": "needs:",
    }

    all_ok = True
    for label, fragment in checks.items():
        if fragment in content:
            print_result(f"Workflow -- {label}", "PASS")
        else:
            print_result(f"Workflow -- {label}", "FAIL", f"'{fragment}' not found")
            all_ok = False
    return all_ok


def test_requirements():
    """Verify backend requirements.txt has essential packages."""
    req_path = Path("backend/requirements.txt")
    if not req_path.exists():
        print_result("requirements.txt exists", "FAIL", "File not found")
        return False

    content = req_path.read_text().lower()

    checks = {
        "Flask": "flask",
        "Gunicorn": "gunicorn",
    }

    all_ok = True
    for label, pkg in checks.items():
        if pkg in content:
            print_result(f"requirements.txt -- {label}", "PASS")
        else:
            print_result(f"requirements.txt -- {label}", "FAIL", f"'{pkg}' not found")
            all_ok = False
    return all_ok


def test_security_no_debug():
    """Verify Flask debug mode is disabled."""
    app_path = Path("backend/app.py")
    if not app_path.exists():
        print_result("backend/app.py exists", "FAIL", "File not found")
        return False

    content = app_path.read_text()

    if "debug=False" in content:
        print_result("Security -- Flask debug mode disabled", "PASS", "debug=False")
        return True
    elif "debug=True" in content:
        print_result("Security -- Flask debug mode disabled", "FAIL", "debug=True found! SECURITY RISK")
        return False
    else:
        print_result("Security -- Flask debug mode disabled", "WARN", "debug not explicitly set (defaults to False in production)")
        return True


def test_security_no_secrets():
    """Check no hardcoded secrets in source files."""
    scan_dirs = ["backend", "frontend/src"]
    secret_patterns = [
        "api_key", "api-key", "api_secret", "api-secret",
        "password", "passwd",
        "secret_key", "secret-key",
        "aws_secret", "aws-secret",
        "-----BEGIN",  # private key
    ]

    found_secrets = []
    for scan_dir in scan_dirs:
        src_dir = Path(scan_dir)
        if not src_dir.exists():
            continue
        for file_path in src_dir.rglob("*"):
            if file_path.is_file() and file_path.suffix in [".py", ".js", ".jsx", ".json"]:
                try:
                    content = file_path.read_text().lower()
                    for pattern in secret_patterns:
                        if pattern in content:
                            # Skip known safe patterns like example keys
                            if "sample_key" in content or "example" in content or "placeholder" in content:
                                continue
                            found_secrets.append(f"{file_path}: contains '{pattern}'")
                except (UnicodeDecodeError, PermissionError):
                    continue

    if found_secrets:
        for s in found_secrets[:5]:
            print_result("Security -- No hardcoded secrets", "WARN", s)
        if len(found_secrets) > 5:
            print(f"    ... and {len(found_secrets)-5} more")
        return False
    else:
        print_result("Security -- No hardcoded secrets", "PASS", "No secrets detected in source code")
        return True


def test_gitignore():
    """Verify .gitignore is configured properly."""
    gitignore_path = Path(".gitignore")
    if not gitignore_path.exists():
        print_result(".gitignore exists", "FAIL", "File not found")
        return False

    content = gitignore_path.read_text()

    required_entries = [
        "node_modules",
        "__pycache__",
        ".env",
        "build",
        ".DS_Store",
        ".mirror-vs",
        "turns.log",
    ]

    all_ok = True
    for entry in required_entries:
        if entry in content:
            print_result(f".gitignore -- '{entry}'", "PASS")
        else:
            print_result(f".gitignore -- '{entry}'", "WARN", f"'{entry}' not in .gitignore")
            all_ok = False
    return all_ok


def run_all_backend_tests():
    """Run all backend-specific tests."""
    print_header("BACKEND API TESTS")
    ok = test_backend_root()
    ok &= test_backend_health()
    ok &= test_backend_pipeline()
    ok &= test_backend_invalid_route()
    ok &= test_backend_response_time()
    ok &= test_backend_headers()
    return ok


def run_all_frontend_tests():
    """Run all frontend-specific tests."""
    print_header("FRONTEND TESTS")
    ok = test_frontend_accessible()
    ok &= test_frontend_spa_shell()
    return ok


def run_all_infrastructure_tests():
    """Run all infrastructure/code quality tests."""
    print_header("DOCKERFILE TESTS")
    ok = test_dockerfile_frontend()
    ok &= test_dockerfile_backend()

    print_header("GITHUB ACTIONS WORKFLOW TESTS")
    ok &= test_workflow_file()

    print_header("DEPENDENCY TESTS")
    ok &= test_requirements()

    print_header("SECURITY TESTS")
    ok &= test_security_no_debug()
    ok &= test_security_no_secrets()

    print_header("CONFIGURATION TESTS")
    ok &= test_gitignore()

    return ok


def print_summary():
    """Print a final summary of all test results."""
    total = passed + failed + warnings
    print()
    print("=" * 60)
    print("  TEST SUMMARY")
    print("=" * 60)
    print(f"\n  Total tests : {total}")
    print(f"  Passed      : {passed}")
    if failed > 0:
        print(f"  Failed      : {failed}")
    else:
        print(f"  Failed      : {failed}")
    if warnings > 0:
        print(f"  Warnings    : {warnings}")
    else:
        print(f"  Warnings    : {warnings}")

    if failed == 0:
        print(f"\n  >>> All tests passed! <<<")
    else:
        print(f"\n  >>> {failed} test(s) failed. Review details above. <<<")

    if warnings > 0:
        print(f"  >>> {warnings} warning(s) -- review recommended but not critical. <<<")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="DevSecOps Pipeline Test Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tests/test_app.py                  # Run all tests
  python tests/test_app.py --backend-only    # Backend API tests only
  python tests/test_app.py --frontend-only   # Frontend tests only
  python tests/test_app.py --infra-only      # Infrastructure tests only
  python tests/test_app.py --verbose         # Detailed output
        """
    )
    parser.add_argument("--backend-only", action="store_true", help="Run only backend API tests")
    parser.add_argument("--frontend-only", action="store_true", help="Run only frontend tests")
    parser.add_argument("--infra-only", action="store_true", help="Run only infrastructure tests")
    parser.add_argument("--verbose", action="store_true", help="Show detailed test output")

    args = parser.parse_args()

    # If no specific flags, run all
    run_all = not (args.backend_only or args.frontend_only or args.infra_only)

    print()
    print("=" * 50)
    print("  DevSecOps Pipeline -- Test Suite")
    print("=" * 50)
    print(f"  Backend : {BACKEND_URL}")
    print(f"  Frontend: {FRONTEND_URL}")
    print(f"  Timeout : {TIMEOUT}s")
    print()

    if run_all or args.backend_only:
        run_all_backend_tests()

    if run_all or args.frontend_only:
        run_all_frontend_tests()

    if run_all or args.infra_only:
        run_all_infrastructure_tests()

    print_summary()

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
