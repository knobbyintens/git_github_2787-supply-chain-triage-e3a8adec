# Dependency Triage Policy

This policy describes how security advisories are converted into remediation
decisions for our internal component inventory.

## Sources

- `registry/components.csv` is the inventory of record. Columns:
  `component_id, service_name, package_name, current_version, environment, owner_team, criticality`.
- `advisories/security_advisories.csv` is the list of security advisories. Columns:
  `advisory_id, cve_id, package_name, affected_min, affected_max, fixed_version, cvss_score, summary`.

## Version matching

Versions are numeric `x.y.z` triples. The affected version range in an advisory
is inclusive on both ends. A component is *affected* only when the package
matches and its deployed version lies within that range.

## Decision rules

- No component uses the package, or no component version is in range:
  `NO_ACTION` with an empty affected-component list.
- At least one affected component runs in `production` and the CVSS score is
  `7.0` or higher: `PATCH_NOW`.
- Any other case with at least one affected component: `PATCH_SCHEDULED`.

## Severity

| CVSS score | Severity |
|------------|----------|
| >= 9.0     | critical |
| 7.0 - 8.9  | high     |
| 4.0 - 6.9  | medium   |
| < 4.0      | low      |

## Remediation priority

- `PATCH_NOW` + `critical` severity: `P0`
- `PATCH_NOW` + any other severity: `P1`
- `PATCH_SCHEDULED` + `critical` or `high` severity: `P2`
- `PATCH_SCHEDULED` + `medium` or `low` severity: `P3`
- `NO_ACTION`: no remediation row

## Reporting

Publish two reports in this repository:

- `triage/vulnerability_triage_report.csv` — header
  `advisory_id,package_name,cve_id,severity,cvss_score,affected_components,decision`.
  One row per advisory; `affected_components` is an alphabetically sorted,
  semicolon-separated list of affected service names (empty when none).
- `triage/remediation_plan.csv` — header
  `advisory_id,decision,owner_teams,priority,fix_version`. One row per advisory
  whose decision is not `NO_ACTION`; `owner_teams` is the alphabetically sorted,
  semicolon-separated set of owning teams of the affected components.
