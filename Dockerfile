# Multi-stage build so the final image carries no build tools for Trivy to flag.
FROM python:3.12-slim AS build
WORKDIR /app
COPY requirements.txt .
# Install deps into a prefix we can copy out, keeping pip/cache out of the runtime.
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim AS runtime
# Create and run as a non-root user: if the app is compromised, the attacker
# does not land as root inside the container. Trivy/Bandit both reward this.
RUN useradd --create-home --uid 10001 appuser
WORKDIR /app
COPY --from=build /install /usr/local
COPY src/ ./src/
USER appuser
EXPOSE 8000
# A HEALTHCHECK so orchestrators (and the CI smoke test) can tell the app is up.
HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/healthz')" || exit 1
# gunicorn (a production WSGI server) instead of the Flask dev server.
CMD ["gunicorn", "--chdir", "src", "--bind", "0.0.0.0:8000", "app:app"]
