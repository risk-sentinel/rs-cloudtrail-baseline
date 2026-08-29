# encoding: UTF-8

control 'C-CT-3.3' do
  title "Ensure CloudTrail Insight events are enabled on at least one trail"
  desc  "
    CloudTrail Insight events flag anomalous management-event volume + error-rate patterns — strong signal for ransomware, account takeover, or runaway IaC. Insight events are not enabled by default; configured via `put_insight_selectors` / `get_insight_selectors`, separate from the management / data event selector configuration.

    This control fails when no visible trail has any insight-event selector configured.
  "
  desc  'rationale', "
    `cis-aws-foundations §5` configures CloudWatch metric filters for specific high-signal events (root login, IAM changes, etc.) — point-in-time alerts. Insight events are the complementary anomaly-based layer: an unusual *rate* of `RunInstances` or `DeleteDBCluster` calls fires regardless of whether each individual call is authorized. This is detection, not prevention; CIS doesn't cover it.
  "
  desc  'check', "
    For every trail, confirm `cloudtrail.get_insight_selectors(trail_name: <arn>)` returns a non-empty `insight_selectors` array. Common values: `ApiCallRateInsight`, `ApiErrorRateInsight`.
  "
  desc  'fix', "
    Enable insight events on a multi-region trail:

    ```
    aws cloudtrail put-insight-selectors \\
      --trail-name <trail-arn> \\
      --insight-selectors \\
        '[{\"InsightType\":\"ApiCallRateInsight\"},{\"InsightType\":\"ApiErrorRateInsight\"}]'
    ```

    Note: insight events incur per-trail cost beyond the base CloudTrail; scope to one organization-trail rather than enabling per-account.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SI-4 (4)', 'AU-6']
  tag nist_r4:               ['AU-6', 'SI-4(4)']
  tag cci:                   ['CCI-000148', 'CCI-002659']
  tag cis_number:            'CT-3.3'
  tag cis_rid:               'CT-3.3'
  tag cis_benchmark:         'the consumer CloudTrail Baseline'
  tag cis_rule_id:           'the consumer-CT-3.3'
  tag cis_version:           '0.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag attestation_category:  'operational'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable           = applicable_partition

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')})") do
    applicable
  end

  describe aws_cloudtrail_insight_selectors(regions: Array(input('scan_regions'))) do
    its('trails_with_insight_events') { should_not be_empty }
  end
end
