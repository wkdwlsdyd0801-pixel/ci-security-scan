# ci-security-scan

A GitHub Actions pipeline that gates a small Flask app on three security scanners: **Bandit** (Python SAST), **Trivy** (dependency, image, config and secret scan) and **gitleaks** (secret scan).

The app in `src/` is written to pass the gate clean. `examples/insecure_patterns.py` holds the same features written insecurely so you can watch Bandit catch them; it is never imported or deployed.

## Run locally

```bash
pip install -r requirements-dev.txt
pytest -q                 # unit tests
make scan                 # bandit + gitleaks + trivy (tools must be installed)
python src/app.py         # serve on http://127.0.0.1:8000
```

Shorten a URL and follow it:

```bash
curl -X POST localhost:8000/shorten -H 'Content-Type: application/json' -d '{"url":"https://example.com"}'
curl -i localhost:8000/r/<code>
```

## CI

`.github/workflows/security-scan.yml` runs on every push/PR (and weekly) and uploads Bandit + Trivy results to the Security tab. Config lives in `bandit.yaml`, `.gitleaks.toml` and `.trivyignore`. Secrets come from the environment only — see `.env.example`.
