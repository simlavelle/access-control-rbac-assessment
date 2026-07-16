#!/usr/bin/env python3
"""
rbac_audit.py — automated RBAC / least-privilege audit.

Given a set of role definitions and each user's actual entitlements, reports:
  - Least-privilege violations : entitlements a user holds that their role does NOT grant.
  - Missing entitlements       : entitlements the role grants that the user lacks.
  - Separation-of-duties (SoD) : users holding a mutually-exclusive pair of permissions.
  - Stale / orphaned accounts  : no login within the configured threshold.

Standard library only. Synthetic data for portfolio use.
"""
import argparse
import csv
import json
import sys


def load_roles(path):
    with open(path) as f:
        return {r: set(p) for r, p in json.load(f).items()}


def load_users(path):
    users = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            users.append({
                "username": row["username"].strip(),
                "role": row["role"].strip(),
                "entitlements": {e.strip() for e in row["entitlements"].split(";") if e.strip()},
                "last_login_days": int(row["last_login_days"]),
            })
    return users


def load_sod(path):
    with open(path) as f:
        data = json.load(f)
    return [tuple(p) for p in data.get("conflicts", [])], int(data.get("stale_threshold_days", 90))


def audit(roles, users, sod_pairs, stale_days):
    findings = []
    for u in users:
        granted = roles.get(u["role"], set())
        if u["role"] not in roles:
            findings.append(("UNKNOWN_ROLE", u["username"], f"role '{u['role']}' not defined"))
        extra = u["entitlements"] - granted
        for e in sorted(extra):
            findings.append(("LEAST_PRIV", u["username"], f"has '{e}' not granted by role '{u['role']}'"))
        missing = granted - u["entitlements"]
        for e in sorted(missing):
            findings.append(("MISSING", u["username"], f"role grants '{e}' but user lacks it"))
        for a, b in sod_pairs:
            if a in u["entitlements"] and b in u["entitlements"]:
                findings.append(("SOD_CONFLICT", u["username"], f"holds conflicting '{a}' + '{b}'"))
        if u["last_login_days"] >= stale_days:
            findings.append(("STALE_ACCOUNT", u["username"], f"no login in {u['last_login_days']} days (>= {stale_days})"))
    return findings


def main():
    p = argparse.ArgumentParser(description="Audit user entitlements against RBAC role definitions.")
    p.add_argument("--roles", required=True)
    p.add_argument("--users", required=True)
    p.add_argument("--sod", required=True)
    args = p.parse_args()

    roles = load_roles(args.roles)
    users = load_users(args.users)
    sod_pairs, stale_days = load_sod(args.sod)

    findings = audit(roles, users, sod_pairs, stale_days)

    print(f"RBAC audit: {len(users)} users, {len(roles)} roles, {len(sod_pairs)} SoD rules\n")
    if not findings:
        print("No findings. Access posture is clean.")
        return
    severity = {"SOD_CONFLICT": 1, "LEAST_PRIV": 2, "UNKNOWN_ROLE": 2, "STALE_ACCOUNT": 3, "MISSING": 4}
    for kind, user, detail in sorted(findings, key=lambda f: (severity.get(f[0], 9), f[1])):
        print(f"  [{kind:14}] {user:10} {detail}")
    high = sum(1 for f in findings if f[0] in ("SOD_CONFLICT", "LEAST_PRIV", "UNKNOWN_ROLE"))
    print(f"\nTotal findings: {len(findings)} ({high} high-priority)")
    sys.exit(1 if high else 0)


if __name__ == "__main__":
    main()
