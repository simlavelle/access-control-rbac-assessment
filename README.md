# Access Control & RBAC Assessment — FinSecure Corp

A security assessment of an organization's access governance, evaluating privilege
assignments, identity-lifecycle enforcement, and access-control policy against
Role-Based Access Control (RBAC) principles and NIST guidance — plus a Python tool that
automates the privilege-audit portion of the review.

> Scenario-based lab. "FinSecure Corp" and all data are fictional/synthetic.

## Scenario

FinSecure Corp requested a review of its access governance, policy alignment, and
operational security. The assessment identified conditions that elevated organizational
risk: **excessive privilege assignments**, **weak identity-lifecycle enforcement** (stale
accounts, no timely deprovisioning), **inconsistent access-control policy**, and informal
operational procedures.

## Approach

Using **RBAC** as the target model and referencing **NIST SP 800-53** access-control
families (AC-2 Account Management, AC-5 Separation of Duties, AC-6 Least Privilege), the
assessment:

1. Inventoried users, roles, and entitlements.
2. Compared each user's effective permissions against the permissions their role *requires*
   (least-privilege gap analysis).
3. Flagged separation-of-duties conflicts (users holding mutually exclusive roles).
4. Identified stale/orphaned accounts that lifecycle controls should have removed.
5. Recommended targeted remediations to strengthen accountability and reduce exposure.

## Key findings (representative)

- **Privilege creep:** several users accumulated entitlements beyond their role as they
  changed positions, violating least privilege (AC-6).
- **Separation-of-duties gaps:** individual accounts held both request and approval rights.
- **Identity lifecycle:** accounts for departed/dormant users remained active.
- **Policy inconsistency:** access decisions were made ad hoc rather than by role definition.

## Recommendations

Define and enforce roles centrally; grant permissions to roles, not individuals; implement
periodic access recertification; automate deprovisioning tied to HR events; and enforce
separation of duties in the role model itself.

## What's in this repo

- `README.md` — this case study.
- `rbac_audit.py` — a Python tool that ingests a role-definition file and a user-entitlement
  file (both CSV/JSON) and reports: least-privilege violations (entitlements a user has but
  their role doesn't grant), missing entitlements, separation-of-duties conflicts, and
  orphaned accounts.
- `data/roles.json` — sample role → allowed-permission definitions.
- `data/user_entitlements.csv` — sample users and their actual entitlements.
- `data/sod_conflicts.json` — sample mutually-exclusive role pairs.
- `sample_output.txt` — example run.

## Running the tool

```bash
python3 rbac_audit.py --roles data/roles.json --users data/user_entitlements.csv --sod data/sod_conflicts.json
```

Standard library only.

## Skills demonstrated

RBAC design · least-privilege / separation-of-duties analysis · identity lifecycle (IAM) ·
NIST SP 800-53 access-control mapping · turning a manual audit into a repeatable script.
