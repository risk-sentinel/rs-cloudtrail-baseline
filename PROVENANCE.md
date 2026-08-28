# Provenance — `rs-cloudtrail-baseline`

## What this profile is (and is not)

This is a **bespoke, Risk Sentinel–authored** AWS CloudTrail baseline — **not** a published CIS
Benchmark. It is styled with `cis_*` tags for tooling consistency, but those values are
self-authored (`cis_benchmark: 'the consumer CloudTrail Baseline'`, custom `CT-#.#` control IDs,
`cis_version` = the profile's own release), so the profile carries **no external benchmark
version**. Its controls are anchored instead to a stack of federal and cloud authoritative
sources, documented here so each check is defensible in an assessment.

Every control maps to one or more NIST SP 800-53 Rev 5 controls (mirrored in each control's
`tag nist:`) and is driven by at least one of the following:

## Authoritative sources

| Key | Source | What it drives here |
|---|---|---|
| **NIST 800-53r5** | NIST SP 800-53 Rev 5 control catalog | The control every check maps to (AU / AC / SC / SI / CP families). |
| **FedRAMP** | FedRAMP Moderate/High baseline | The audit-family requirements + enhancements (AU-6(3)/(4), AU-9(2), AU-11) behind org-trail coverage, tamper-resistance, and retention. |
| **CSP SRG** | DoD Cloud Computing SRG | Cloud-service-provider audit/logging requirements for the authorization boundary. |
| **OMB M-21-31** | OMB Memorandum M-21-31 | Federal event-logging maturity + retention mandate (12 months hot + 18 months cold = 30 months) — drives the CWL retention floor. |
| **AWS FSBP** | AWS Foundational Security Best Practices + Well-Architected Security pillar | The AWS-native CloudTrail controls (multi-region/org trails, data events, log validation, encryption in transit, Object Lock). |

**"Beyond CIS":** several controls (CT-3.1, CT-5.1, and the org-trail/Insight/Object-Lock checks)
address surfaces CIS does not cover at all — they exist because FedRAMP / OMB / FSBP require them,
which is precisely why this profile is not a CIS derivative.

## Control provenance

| § | Control | Verifies | NIST 800-53r5 | Primary source(s) | Rationale (risk addressed) |
|---|---|---|---|---|---|
| 1 · Trail health | **CT-1.1** | Trails are actively logging (`IsLogging == true`) | AU-12 | FedRAMP, FSBP | A disabled trail produces no evidence — the whole audit record depends on this. |
| | **CT-1.2** | Latest delivery is recent and error-free | AU-12, AU-9 | FedRAMP | A silently failing trail is indistinguishable from no logging; delivery health = audit integrity. |
| | **CT-1.3** | Digest delivery is error-free (validates the §4.3 delivery chain) | AU-9, AU-10 | FedRAMP, FSBP | Non-repudiation: the digest/log-file-validation chain proves logs weren't tampered with. |
| 2 · Org coverage | **CT-2.1** | At least one trail is an organization trail | AU-6 (3), AU-12 | FedRAMP, FSBP | Centralized cross-account evidence is the substrate every downstream detection/response control sits on. |
| | **CT-2.2** | Org-trail destination bucket is in the approved log-archive allowlist | AU-9 (2) | FedRAMP, FSBP (WA) | Evidence must live in a dedicated security/log-archive account, not a workload or management account. |
| | **CT-2.3** | Org trail covers every active member account | AU-6 (4) | FedRAMP, CSP SRG | Coverage gaps = blind spots in multi-account investigations (attestation-backed for account inventory). |
| 3 · Event capture | **CT-3.1** | At least one trail captures Lambda invoke data events | AU-12, AU-2 | FedRAMP, FSBP (WA) | Serverless is an audit blind spot without invoke-data-event logging; **CIS does not cover this**. |
| | **CT-3.2** | S3 data events cover the consumer-supplied required-bucket-ARN list | AU-12 (1), AC-3 | FedRAMP | Data-plane access to sensitive buckets must be auditable, not just control-plane events. |
| | **CT-3.3** | CloudTrail Insight events are enabled on ≥1 trail | SI-4 (4), AU-6 | FSBP (WA) | Behavioral anomaly detection over the API call stream (unusual write/error volumes). |
| 4 · CWL integration | **CT-4.1** | Every trail forwards to CloudWatch Logs | AU-6 (1), SI-4 (5) | FedRAMP, FSBP | Real-time analysis/alerting requires the live CWL query layer, not just the S3 archive. |
| | **CT-4.2** | CWL log groups meet the retention floor (default 365d) | AU-11 | **OMB M-21-31**, FedRAMP | Federal log-retention mandate; the live-query layer must cover the audit window (the 30-month total). |
| | **CT-4.3** | CloudTrail→CWL delivery is recent and error-free | AU-12, SI-4 | FedRAMP | A broken CWL delivery silently defeats CT-4.1's real-time analysis. |
| 5 · Bucket integrity | **CT-5.1** | Destination buckets have S3 Object Lock enabled | AU-9, AU-9 (2) | FedRAMP | Tamper-resistance: a compromised privileged role otherwise deletes the audit trail; **CIS does not cover this** — AU-9(2) is the canonical control. |
| | **CT-5.2** | Bucket policy denies non-TLS PUT | SC-8, SC-13 | FedRAMP, FSBP | Evidence must be encrypted in transit to the archive. |
| | **CT-5.3** | Buckets transition to Glacier within threshold | AU-11, CP-9 | FedRAMP, OMB M-21-31 | Long-term retention + cost-managed archival for the cold-storage portion of the audit window. |

## Notes

- **Control IDs** use a `CT-<section>.<n>` scheme (author-assigned), grouped 1–5 above.
- **NIST mappings** here mirror each control's `tag nist:`; they are the authoritative
  cross-reference for OSCAL/Heimdall rollup.
- **Attestation-backed:** CT-2.3 relies on a consumer-supplied account inventory
  (`organizations_attestation_reference`) where the API cannot enumerate authoritatively.
- Keep it in sync when controls are added, removed, or re-anchored.

