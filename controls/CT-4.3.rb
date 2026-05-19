# encoding: UTF-8

control 'C-CT-4.3' do
  title "Ensure CloudTrail-to-CWL delivery is recent and error-free"
  desc  "
    Like CT-1.2 (S3 delivery health), the CWL delivery path can fail silently — typically due to the trail's CloudWatch Logs role being deleted, lacking `logs:CreateLogStream` / `logs:PutLogEvents`, or the destination log group being deleted.

    `LatestCloudWatchLogsDeliveryTime` and `LatestCloudWatchLogsDeliveryError` from `get_trail_status` reveal it. This control fails when any trail's last CWL delivery is older than `trail_delivery_recency_hours` (default 24h) or has a non-empty error.

    Trails with no CWL destination configured at all are out of scope here (they're caught by CT-4.1).
  "
  desc  'rationale', "
    A trail with CWL forwarding configured but a broken IAM role produces no §5 metric-filter alerts even though §4 + CT-4.1 both pass. Without a delivery-health check, the gap is invisible until investigated.
  "
  desc  'check', "
    For every trail with a CWL destination configured, confirm:

    - `LatestCloudWatchLogsDeliveryTime` within the recency threshold
    - `LatestCloudWatchLogsDeliveryError` is empty
  "
  desc  'fix', "
    Re-create the CloudTrail CWL role with the canonical permissions, or fix the failing log group / log stream. Test with:

    ```
    aws cloudtrail get-trail-status --name <trail-arn>
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AU-12', 'SI-4']
  tag cis_number:            'CT-4.3'
  tag cis_rid:               'CT-4.3'
  tag cis_benchmark:         'the consumer CloudTrail Baseline'
  tag cis_rule_id:           'the consumer-CT-4.3'
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

  describe aws_cloudtrail_trail_status(regions: Array(input('scan_regions')),
                                        delivery_recency_hours: input('trail_delivery_recency_hours')) do
    its('trails_with_stale_cwl_delivery') { should be_empty }
  end
end
