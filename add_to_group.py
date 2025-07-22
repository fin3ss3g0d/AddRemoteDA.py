#!/usr/bin/env python3
"""
add_to_group.py – add an existing user to an AD group.

Use --ssl for LDAPS; default is LDAP on port 389.  Specify --port to override.
"""
import argparse, ssl, sys
from ldap3 import Server, Connection, NTLM, ALL, Tls
from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError

# ───── args ─────────────────────────────────────────────────────────────────
ap = argparse.ArgumentParser(description="Add user to group (LDAP/LDAPS)")
ap.add_argument("--dc-ip", required=True); ap.add_argument("--port", type=int)
ap.add_argument("--ssl", action="store_true",
                help="Enable LDAPS (default LDAP).")
ap.add_argument("--insecure", action="store_true",
                help="Skip cert validation if --ssl.")
ap.add_argument("--domain", required=True); ap.add_argument("--user", required=True)
au = ap.add_mutually_exclusive_group(required=True)
au.add_argument("--password"); au.add_argument("--hashes")
ap.add_argument("--target-user", required=True); ap.add_argument("--target-group", required=True)
ap.add_argument("--user-dn"); ap.add_argument("--group-dn")
ap.add_argument("--user-ou", default="CN=Users"); ap.add_argument("--group-ou", default="CN=Users")
ap.add_argument("--debug", action="store_true")
args = ap.parse_args()

def dbg(m): print(f"[DEBUG] {m}") if args.debug else None
def build_dn(cn, ou): return f"CN={cn},{ou}," + ",".join(f"DC={x}" for x in args.domain.split("."))

port = args.port if args.port else (636 if args.ssl else 389)
tls = Tls(validate=ssl.CERT_NONE if args.insecure else ssl.CERT_REQUIRED) if args.ssl else None
srv = Server(args.dc_ip, port=port, use_ssl=args.ssl, get_info=ALL, tls=tls)
dbg(f"Connecting {'LDAPS' if args.ssl else 'LDAP'} {args.dc_ip}:{port}")

try:
    conn = Connection(srv, user=f"{args.domain}\\{args.user}",
                      password=args.password or args.hashes,
                      authentication=NTLM, auto_bind=True, raise_exceptions=True)
except (LDAPSocketOpenError, LDAPException) as e:
    sys.exit(f"[!] Bind failed: {e}")

user_dn  = args.user_dn  or build_dn(args.target_user,  args.user_ou)
group_dn = args.group_dn or build_dn(args.target_group, args.group_ou)
try:
    conn.extend.microsoft.add_members_to_groups([user_dn], [group_dn])
    print(f"[+] {args.target_user} added to {args.target_group}")
except LDAPException as e:
    sys.exit(f"[!] Failure: {e}")
