#!/usr/bin/env python3
"""
add_da.py – create a Domain Admin account (requires LDAPS).

Only the --port value is user‑selectable; TLS is always enabled.
"""
import argparse, ssl, secrets, string, sys
from typing import Tuple
from ldap3 import Server, Connection, NTLM, ALL, MODIFY_REPLACE, Tls
from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError

# account‑control flags
NORMAL_ACCOUNT = 0x0200
ACCOUNTDISABLE = 0x0002
UAC_DISABLED   = NORMAL_ACCOUNT | ACCOUNTDISABLE      # 514
UAC_ENABLED    = NORMAL_ACCOUNT                       # 512 (pwd will expire)

# ───── helper funcs ──────────────────────────────────────────────────────────
def strong_pwd(n=50):
    pools = [string.ascii_uppercase, string.ascii_lowercase,
             string.digits, "!@#$%^&*()-_=+[]{}"]
    while True:
        p = "".join(secrets.choice("".join(pools)) for _ in range(n))
        if sum(any(c in pool for c in p) for pool in pools) >= 3:
            return p

def dns(domain, sam, container, da_cn=None) -> Tuple[str, str]:
    base = ",".join(f"DC={x}" for x in domain.split("."))
    user_dn = f"CN={sam},{container},{base}"
    group_dn = f"{da_cn},{base}" if da_cn else f"CN=Domain Admins,CN=Users,{base}"
    return user_dn, group_dn

# ───── args ─────────────────────────────────────────────────────────────────
ap = argparse.ArgumentParser(description="Add a Domain Admin via LDAPS")
ap.add_argument("--dc-ip", required=True);              ap.add_argument("--port", type=int, default=636)
ap.add_argument("--domain", required=True);             ap.add_argument("--user", required=True)
auth = ap.add_mutually_exclusive_group(required=True)
auth.add_argument("--password");                        auth.add_argument("--hashes")
ap.add_argument("--new-user", required=True);           ap.add_argument("--new-pass")
ap.add_argument("--ou", default="CN=Users")
ap.add_argument("--da-cn", help="Custom CN path for Domain Admins group (e.g., 'CN=Admins,CN=CustomOU')")
ap.add_argument("--insecure", action="store_true");     ap.add_argument("--debug", action="store_true")
args = ap.parse_args()

dbg = (lambda m: print(f"[DEBUG] {m}")) if args.debug else (lambda *_: None)

tls = Tls(validate=ssl.CERT_NONE if args.insecure else ssl.CERT_REQUIRED,
          version=ssl.PROTOCOL_TLSv1_2)
srv = Server(args.dc_ip, port=args.port, use_ssl=True, get_info=ALL, tls=tls)
dbg(f"Connecting LDAPS {args.dc_ip}:{args.port}")

try:
    conn = Connection(srv, user=f"{args.domain}\\{args.user}",
                      password=args.password or args.hashes,
                      authentication=NTLM, auto_bind=True, raise_exceptions=True)
except (LDAPSocketOpenError, LDAPException) as e:
    sys.exit(f"[!] Bind failed: {e}")

user_dn, da_dn = dns(args.domain, args.new_user, args.ou, args.da_cn)
dbg(f"User DN: {user_dn}, DA DN: {da_dn}")
pwd = args.new_pass or strong_pwd()
print(f"[+] Using password: {pwd}")

attrs = {"objectClass": ["user"], "sAMAccountName": args.new_user,
         "userPrincipalName": f"{args.new_user}@{args.domain}",
         "userAccountControl": UAC_DISABLED}

try:
    conn.add(user_dn, attributes=attrs)
    dbg(f"User {args.new_user} added with DN: {user_dn}")
    conn.extend.microsoft.modify_password(user_dn, pwd)
    dbg(f"Password for {args.new_user} set to: {pwd}")
    conn.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, [UAC_ENABLED])]})
    dbg(f"User {args.new_user} enabled with UAC: {UAC_ENABLED}")
    conn.extend.microsoft.add_members_to_groups([user_dn], [da_dn])
    dbg(f"User {args.new_user} added to Domain Admins group: {da_dn}")
    print(f"[+] {args.new_user} added to Domain Admins (pwd will expire).")
except LDAPException as e:
    sys.exit(f"[!] Failure: {e}")
