"""
A small Flask URL-shortener API, written to pass the security scanners in CI.

This file is the "clean" codebase: the GitHub Actions pipeline runs Bandit
(Python SAST), Trivy (dependency/image/config/secret scan) and gitleaks
(secret scan) against the repo on every push. The gating scan over src/ is
expected to report zero issues, so every design choice below is a defence a
scanner would otherwise flag:

  - secrets come from the environment, never from the source (gitleaks)
  - subprocess / eval / pickle are never used (Bandit)
  - tokens use secrets.token_urlsafe, not random (Bandit weak-randomness)
  - the debug server is gated behind an explicit env flag (Bandit B201)

Compare this with examples/insecure_patterns.py, which keeps the same features
written the wrong way so you can watch Bandit catch each pattern.
"""
import os
import re
import secrets

from flask import Flask, abort, jsonify, redirect, request


def create_app(store=None):
    """Build the Flask app. `store` is injected so tests can pass a fresh dict."""
    app = Flask(__name__)

    # The link store maps short code -> target URL. In-memory is fine for a lab;
    # a real deployment would use a database, which Trivy would then scan the
    # image of. Passing it in keeps the app stateless and unit-testable.
    links = store if store is not None else {}

    # Only http/https targets are accepted. Without this check an attacker could
    # store javascript: or file: URLs and turn the shortener into an open
    # redirect to dangerous schemes.
    allowed_scheme = re.compile(r"^https?://", re.IGNORECASE)

    @app.post("/shorten")
    def shorten():
        # request.get_json(silent=True) returns None on bad input instead of
        # raising, so malformed bodies become a clean 400 rather than a 500 that
        # could leak a stack trace.
        data = request.get_json(silent=True) or {}
        url = data.get("url", "")

        # Reject anything that is not a plain http(s) URL before storing it.
        if not isinstance(url, str) or not allowed_scheme.match(url):
            abort(400, description="url must start with http:// or https://")

        # token_urlsafe draws from os.urandom (a CSPRNG). random.choice would be
        # predictable, letting someone enumerate or forge short codes.
        code = secrets.token_urlsafe(6)
        links[code] = url
        return jsonify({"code": code, "short_url": f"/r/{code}"}), 201

    @app.get("/r/<code>")
    def resolve(code):
        # Look the code up instead of interpolating it into anything. There is no
        # SQL or shell here, so the user-controlled code can never become code.
        target = links.get(code)
        if target is None:
            abort(404)
        return redirect(target, code=302)

    @app.get("/healthz")
    def healthz():
        # A liveness endpoint the Dockerfile HEALTHCHECK and CI smoke test hit.
        return jsonify({"status": "ok", "links": len(links)})

    return app


app = create_app()


if __name__ == "__main__":
    # Never hard-code debug=True: Bandit flags B201 because the Werkzeug debugger
    # allows remote code execution. Debug is opt-in through an env var and off by
    # default, and the host is read from the environment too.
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    app.run(host=host, port=port, debug=debug)
