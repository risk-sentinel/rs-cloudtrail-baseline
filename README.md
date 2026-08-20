# rs-cloudtrail-baseline

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=risk-sentinel_cis-cloudtrail)](https://sonarcloud.io/summary/new_code?id=risk-sentinel_cis-cloudtrail)

InSpec / CINC Auditor profile validating **AWS CloudTrail** configuration and
log-pipeline health — 15 controls across trail coverage, log-archive provenance,
data-event recording, delivery health, and retention/lifecycle.

No CIS Benchmark covers CloudTrail as a subject in its own right. Controls are
anchored to **NIST 800-53 r5** (AU family primarily), **AWS Foundational Security
Best Practices**, and the AWS CloudTrail security best-practices guidance. The
full derivation is in [`PROVENANCE.md`](PROVENANCE.md) — read it before adopting
this as evidence, because a bespoke baseline is only as good as its stated basis.

Targets **AWS Commercial** and **AWS GovCloud (non-DoD)**. Per-control partition
applicability is in [`partition_applicability.yml`](partition_applicability.yml)
and encoded as `tag applicable_partitions:`.

---

## Quickstart

```bash
git clone https://github.com/risk-sentinel/rs-cloudtrail-baseline
cd rs-cloudtrail-baseline

cp inputs/example.yml inputs/mine.yml     # then edit — see Inputs below
cinc-auditor vendor . --overwrite

cinc-auditor exec . -t aws:// \
  --input-file inputs/mine.yml \
  --reporter cli json:results.json
```

`--input-file` is **not optional**. cinc-auditor does not auto-load a
profile-root inputs file, and three controls here scope themselves out on an
empty input — so leaving it off produces a quieter run, not a failing one.

### Credentials

Standard AWS credential resolution. Read-only across the trail pipeline:

```
cloudtrail:DescribeTrails  cloudtrail:GetTrailStatus  cloudtrail:GetEventSelectors
s3:GetBucketPolicy  s3:GetBucketVersioning  s3:GetBucketLifecycleConfiguration
s3:GetBucketPublicAccessBlock  s3:GetEncryptionConfiguration
logs:DescribeLogGroups  logs:DescribeMetricFilters  kms:DescribeKey
ec2:DescribeRegions       organizations:ListAccounts   (optional — see below)
```

`organizations:ListAccounts` is optional. Without it, organization-trail member
coverage cannot be verified from a workload account, and
`organizations_attestation_reference` is how you record that it is satisfied
another way.

### What a first run looks like

Against a real account, with the allow-lists left empty:

**15 controls, 16 results — roughly 8 passed / 6 failed / 2 skipped.**

If you see far fewer, that is the signal to investigate. A run that assessed
nothing exits 0 and looks clean.

---

## Inputs

Fully documented in [`inputs/example.yml`](inputs/example.yml).

| Group | Inputs |
|---|---|
| **Required** | `aws_partition` |
| **Scoping** | `scan_regions` — empty means dynamic discovery; narrowing makes the scan faster **and blinder** |
| **Thresholds** | `trail_delivery_recency_hours`, `cwl_retention_min_days`, `trail_bucket_glacier_transition_days` |
| **Allow-lists** | `approved_trail_buckets`, `required_data_event_bucket_arns` |
| **Attestation** | `organizations_attestation_reference`, `c_ct_2_3_attestation_uri`, the `*_base` URIs |

**The two allow-lists are where controls go quiet.** `approved_trail_buckets`
empty skips C-CT-2.2, and `required_data_event_bucket_arns` empty skips C-CT-3.2.
Neither can be inferred — the profile cannot know your log-archive design, and
guessing would be worse than declining to answer — so both skip with a rationale
rather than passing. Populate them to actually enforce those controls.

---

## Controls

15 controls in five themes:

| Theme | Assesses |
|---|---|
| 1 — Coverage | a multi-region trail exists, is logging, and validates log-file integrity |
| 2 — Provenance | the trail's destination bucket is approved, private, encrypted and versioned |
| 3 — Data events | management events plus S3 data events for the buckets you name |
| 4 — Delivery health | recent delivery to S3 and CloudWatch Logs, and CWL retention |
| 5 — Retention | lifecycle transition to Glacier / Deep Archive within a threshold |

---

## Producing evidence

A `--reporter cli` run tells you the answer. It does not produce something an
assessor can trace back to what was assessed, when, by whom, or from which
scanner output. For that, use the CI templates — the whole pipeline, in YAML
with no helper scripts behind it:

**GitHub**

```yaml
jobs:
  evidence:
    uses: risk-sentinel/rs-cloudtrail-baseline/.github/workflows/exec-evidence.yml@main
    with:
      target: my-account
      profile_name: cis-cloudtrail
      profile_version: "0.1.0"
    secrets:
      AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
```

**GitLab**

```yaml
include:
  - project: risk-sentinel/rs-cloudtrail-baseline
    file: /ci/gitlab/exec-evidence.yml
    inputs:
      target: my-account
      profile_name: cis-cloudtrail
      profile_version: "0.1.0"
```

An `include:` brings YAML and nothing else, which is why the logic lives in the
YAML rather than in a script an including project would never receive. The
templates are carried in this repository on purpose: clone it or include it and
you have the entire pipeline, with nothing else to install.

### The order, and why it is that order

```
create passthrough -> execute -> convert (gate) -> apply -> label (gate)
                   -> validate (gate) -> display
```

The audit record is built **before** the scan, because that is when the honest
start time and the pipeline provenance are known. Only finish time, the artifact
digest and the outcome counts are added afterwards.

### Two artifacts

| artifact | shape | for |
|---|---|---|
| `results.final.json` | HDF v3 `baselines[]` | authoritative evidence — schema-validated, carries the audit record and typed target components, feeds `hdf convert --to oscal-sar` |
| `results-heimdall.json` | InSpec exec-json `profiles[]` | loading into Heimdall |

The Heimdall artifact is a **copy, not a conversion**. Tested against a live
Heimdall: every `profiles[]` variant loads, including the output of both
`--to hdf@1` and `--to hdf@2`; only the `baselines[]` v3 document is refused. So
the choice is fidelity, and every conversion path drops `resource_params` from
each result plus `depends` / `status` / `status_message` from the profile.
Copying what cinc-auditor already wrote loses nothing.

**Do not reach for `hdf convert --to hdf@2`.** The `hdf@N` namespace was
renumbered between hdf-libs 3.4.1 and 3.5.1 — on 3.4.1 it emits `baselines[]`,
on 3.5.1 `profiles[]` — so a pipeline pinned to it silently changes artifact
across an image bump. On 3.5.1, `@1` and `@2` are byte-identical.

### Three gates, each of which has failed silently in this estate

- `hdf convert` without `--no-validate`
- `hdf label` followed by `hdf label show | grep '^Component:'` — `label set`
  prints `Labels written` and writes a byte-identical file when the document has
  no components
- `hdf validate`

The exec step additionally fails the job on a missing or **zero-result**
artifact. A run that assessed nothing must not go green.

### The audit record

Written on every run — clean, failed, findings or none. Target, scan window,
scanner, profile and version, pipeline provenance, actor, converter, a sha256 of
the pre-conversion artifact, and outcome counts.

Two properties are deliberate: **absent is not empty** (an inapplicable field is
omitted, an undeterminable one is `null` with a reason), and the record **marks
which fields are corroborable** against systems the producer does not control.
An audit chain where every field is self-asserted is a story.

Schema authority: [dev-sec-ops-baseline#33](https://github.com/risk-sentinel/dev-sec-ops-baseline/issues/33).

---

## Consuming this profile

Depend on it rather than forking, so you get fixes:

```yaml
depends:
  - name: cis-cloudtrail
    git: https://github.com/risk-sentinel/rs-cloudtrail-baseline.git
    tag: v0.1.4
```

Then `include_controls 'cis-cloudtrail'` and supply your own inputs. Input overrides
reach the depended profile's controls, so your values win without editing
anything here.

## Contributing

Control logic changes belong here. `cinc-auditor check` only *loads* a profile —
it will not catch a resource that returns empty because an API call failed.
Anything touching `libraries/` needs a real `exec` against a real target before
it is trusted.

## License

Apache-2.0. See [LICENSE](LICENSE).
