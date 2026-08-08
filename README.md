# cis-cloudtrail

Tier-2 baseline for AWS CloudTrail covering surfaces beyond `cis-aws-foundations §4`. Targets AWS Commercial (`aws`) and AWS GovCloud non-DoD (`aws-us-gov`). Per-control partition applicability is documented in [`partition_applicability.yml`](partition_applicability.yml) and encoded as `tag applicable_partitions:`.

Risk-Sentinel-attributed and consumer-agnostic, consistent with the rest of the `cis-*` profiles in this repo. The the consumer consumer overlay lives at [`examples/sparc.inputs.yml`](examples/sparc.inputs.yml). Renamed from `sparc-cloudtrail-baseline` (#11) to `cis-cloudtrail` (#77) before the v0.1.0 tag — the legacy name is gone, no shim.

## Themes

| Theme | Concern | Controls |
|---|---|---|
| 1 | Trail health (vs. just "trail exists") | C-CT-1.1 / 1.2 / 1.3 |
| 2 | Multi-account aggregation | C-CT-2.1 / 2.2 / 2.3 |
| 3 | Deeper event selectors | C-CT-3.1 / 3.2 / 3.3 |
| 4 | CloudWatch Logs integration | C-CT-4.1 / 4.2 / 4.3 |
| 5 | Trail-bucket tamper resistance | C-CT-5.1 / 5.2 / 5.3 |

## Delineation from `cis-aws-foundations §4`

`cis-aws-foundations §4` is the **CIS-baseline CloudTrail surface** — trail enabled, log file validation, KMS encryption of logs, S3 access logging on the trail bucket, S3 object-level read/write logging via the `aws_cloudtrail_event_selectors` custom resource (added by sparc-validate#20).

`cis-cloudtrail` adds the surfaces CIS doesn't cover:

- **§4 says trail is enabled.** This profile says the trail is *actually delivering events* (`IsLogging`, `LatestDeliveryTime`).
- **§4 covers single-account trails.** This profile covers organization trails + log-archive bucket provenance.
- **§4 covers S3 read/write data events.** This profile adds Lambda data events, S3 data event scoping to specific buckets, and Insight events.
- **§4 covers KMS encryption + S3 access logging on the trail bucket.** This profile adds CloudWatch Logs integration health + trail bucket tamper resistance (Object Lock, TLS-deny, lifecycle).

If you adopt this profile, run it **alongside** `cis-aws-foundations` — the two are designed to be additive. Foundations gives you the CIS-baseline coverage; this profile gives you the deeper FedRAMP-aligned controls.

## Inputs

See [`inputs.yml`](inputs.yml) for the full catalogue. The most commonly tuned:

- `trail_delivery_recency_hours` (default 24h) — Theme 1.2 / 4.3 freshness threshold.
- `approved_trail_buckets` (default `[]`) — Theme 2.2 log-archive allowlist; empty skips with attestation rationale.
- `required_data_event_bucket_arns` (default `[]`) — Theme 3.2 scope; empty skips with attestation rationale.
- `cwl_retention_min_days` (default 365) — Theme 4.2 retention floor.
- `trail_bucket_glacier_transition_days` (default 90) — Theme 5.3 lifecycle floor.
- `c_ct_2_3_attestation_uri` (default `''`) — C-CT-2.3 workload-account fallback. When `organizations:ListAccounts` is unreachable, points `document_attestation` at the member-coverage review evidence (`s3://`/`https://`/`file://`); set it to lift the fallback from Skip to Pass-with-evidence (`c_ct_2_3_attestation_max_age_days` sets the staleness window, default 365).

## Custom resources

Under `libraries/`:

- `_aws_backend_bootstrap.rb` — vendored-inspec-aws `$LOAD_PATH` setup; required so `aws_backend` resolves at exec time. See `cis-aws-foundations/libraries/_aws_backend_bootstrap.rb` and sparc-validate#24.
- `aws_cloudtrail_trail_status.rb` — wraps `cloudtrail.get_trail_status` for every trail; surfaces `is_logging`, `latest_delivery_time`, `latest_delivery_error`, `latest_digest_delivery_error`, `latest_cloud_watch_logs_delivery_time`, plus a top-level `unhealthy_trails` violations array.
- `aws_cloudtrail_data_event_coverage.rb` — joins `describe_trails` × `get_event_selectors` to assert per-bucket / per-Lambda data event coverage with structured `missing_resources` violations.
- `aws_cloudtrail_insight_selectors.rb` — wraps `cloudtrail.get_insight_selectors` (not exposed by vendored inspec-aws).
- `aws_organization_member_coverage.rb` — best-effort `organizations.list_accounts` enumeration with a `connection_error` accessor for the workload-account `AccessDenied` case (per `Vendored_Resource_Gaps.md` §5).
- `aws_s3_bucket_features.rb` — composite resource exposing `object_lock_configuration`, `bucket_policy_doc`, `lifecycle_rules` (each from a separate SDK call) for the trail bucket; pairs with parsing helpers in `iam_policy_statement_helpers.rb`.
- `document_attestation.rb` — source-agnostic existence + freshness accessor for an evidence document at a URI (`s3://`/`https://`/`file://`); lifts attestation fallbacks from Skip to Pass-with-evidence. Copied verbatim from `cis-aws-foundations` per `feedback_each_profile_stands_alone` (sparc-validate#115).

## Validation

```bash
# Syntax check
docker run --rm -v "$PWD:/work" -w /work \
  risksentinel/cinc-auditor@sha256:<digest-from-Image_Pinning_Policy.md> \
  check profiles/cis-cloudtrail

# Exec-time library load check (catches what `check` doesn't)
docker run --rm -v "$PWD:/work" -w /work \
  risksentinel/cinc-auditor@sha256:<digest> \
  json profiles/cis-cloudtrail

# Vendor before exec
docker run --rm -v "$PWD:/work" -w /work \
  risksentinel/cinc-auditor@sha256:<digest> \
  vendor profiles/cis-cloudtrail --overwrite

# Full execution
docker run --rm \
  -v "$PWD:/work" -w /work \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \
  -e AWS_REGION=us-east-1 \
  risksentinel/cinc-auditor@sha256:<digest> \
  exec profiles/cis-cloudtrail -t aws:// \
  --input-file profiles/cis-cloudtrail/inputs.yml \
  --reporter cli json:hdf.json
```

## Coverage distribution

Final state (post-build):

| Type | `implementation_status` | Count |
|---|---|---|
| Automated | `implemented` | 14 |
| Attestation fallback | `alternative` | 1 (C-CT-2.3 when Organizations API unreachable) |
| Pending | `planned` | 0 |

C-CT-2.3 is the only control with a conditional path: from a management account it runs as automated; from a workload account `organizations:ListAccounts` returns `AccessDenied` and the control falls back to attestation rationale (CMS-pattern). The control body uses the connection-precheck pattern from `docs/dev/Vendored_Resource_Gaps.md` §5.

`attestation_category` breakdown: 14 `operational` (engineering / SecOps reviews delivery health, event-selector scope, retention, lifecycle); 1 `policy` (C-CT-2.2 — bucket-allowlist provenance is a governance review).

## Per-control map

| Control | Theme | Status | Category | NIST | Resource(s) used |
|---|---|---|---|---|---|
| C-CT-1.1 | Trail health | implemented | operational | AU-12 | `aws_cloudtrail_trail_status` |
| C-CT-1.2 | Trail health | implemented | operational | AU-12, AU-9 | `aws_cloudtrail_trail_status` |
| C-CT-1.3 | Trail health | implemented | operational | AU-9, AU-10 | `aws_cloudtrail_trail_status` |
| C-CT-2.1 | Multi-account | implemented | operational | AU-6 (3), AU-12 | `aws_cloudtrail_trail_status` |
| C-CT-2.2 | Multi-account | implemented | policy | AU-9 (2) | `aws_cloudtrail_trail_status` |
| C-CT-2.3 | Multi-account | alternative | policy | AU-6 (4) | `aws_organization_member_coverage` |
| C-CT-3.1 | Event selectors | implemented | operational | AU-12, AU-2 | `aws_cloudtrail_data_event_coverage` |
| C-CT-3.2 | Event selectors | implemented | operational | AU-12 (1), AC-3 | `aws_cloudtrail_data_event_coverage` |
| C-CT-3.3 | Event selectors | implemented | operational | SI-4 (4), AU-6 | `aws_cloudtrail_insight_selectors` |
| C-CT-4.1 | CWL integration | implemented | operational | AU-6 (1), SI-4 (5) | `aws_cloudtrail_trail_status` |
| C-CT-4.2 | CWL integration | implemented | operational | AU-11 | `aws_cwl_log_group_retention` |
| C-CT-4.3 | CWL integration | implemented | operational | AU-12, SI-4 | `aws_cloudtrail_trail_status` |
| C-CT-5.1 | Bucket tamper resistance | implemented | operational | AU-9, AU-9 (2) | `aws_s3_bucket_features` |
| C-CT-5.2 | Bucket tamper resistance | implemented | operational | SC-8, SC-13 | `aws_s3_bucket_features` |
| C-CT-5.3 | Bucket tamper resistance | implemented | operational | AU-11, CP-9 | `aws_s3_bucket_features` |

## Related

- `docs/dev/Implementation_plan.md` — Phase 3 sequencing.
- `docs/dev/Vendored_Resource_Gaps.md` — patterns for the custom resources here.
- `docs/dev/Attestation_Strategy.md` — CMS-pattern attestation used by C-CT-2.3's fallback.
- Issue: [#11](../../issues/11) — scoping comment + acceptance criteria.

---

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=risk-sentinel_cis-cloudtrail)](https://sonarcloud.io/summary/new_code?id=risk-sentinel_cis-cloudtrail)
