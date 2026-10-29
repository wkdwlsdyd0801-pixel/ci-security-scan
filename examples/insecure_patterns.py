"""
The same shortener features written the WRONG way, kept here on purpose.

This file is NEVER imported by the app and NEVER deployed. The CI pipeline runs
a separate, non-gating Bandit job over examples/ so the workflow log shows the
scanner catching each anti-pattern below. Every function here is a vulnerability
on purpose - do not copy it into real code.
"""
import hashlib
import os
import random
import subprocess  # nosec B404 - imported only to demonstrate the shell issue below


def weak_code():
    # Bandit B311: random is not cryptographically secure, so generated codes
    # are predictable and can be guessed or enumerated.
    return "".join(random.choice("abcdef0123456789") for _ in range(6))


def weak_hash(password):
    # Bandit B324: MD5 is broken for passwords - fast to brute-force and with
    # known collisions. A real app would use a slow salted KDF.
    return hashlib.md5(password.encode()).hexdigest()


def fetch_title(url):
    # Bandit B602/B605: passing user input to a shell with shell=True lets an
    # attacker inject commands, e.g. url = "x; rm -rf /".
    return subprocess.check_output(f"curl -s {url}", shell=True)


def run_rule(expr):
    # Bandit B307: eval executes arbitrary Python from its argument - full RCE
    # if `expr` is attacker-controlled.
    return eval(expr)


def temp_file():
    # Bandit B108: a predictable path in /tmp is a race / symlink-attack target.
    path = "/tmp/shortener.db"
    with open(path, "w") as f:
        os.chmod(path, 0o777)  # Bandit B103: world-writable file.
        f.write("data")
    return path
