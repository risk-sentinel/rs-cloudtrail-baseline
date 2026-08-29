# encoding: UTF-8

control 'C-CT-1.2' do
  title "Ensure CloudTrail latest delivery is recent and error-free"
  desc  "
    `LatestDeliveryTime` records the most recent successful S3 archive write; `LatestDeliveryError` records the most recent failure. Both fields come from `cloudtrail.get_trail_status`. A trail can be `IsLogging == true` (CT-1.1 passes) but still failing to deliver — typical causes: bucket-policy regression denying `cloudtrail.amazonaws.com`, KMS key policy denying `cloudtrail.amazonaws.com:GenerateDataKey`, or the bucket itself deleted.

    This control fails when any trail has either no recent successful delivery (older than `trail_delivery_recency_hours` input, default 24h) or a non-empty `LatestDeliveryError`.
  "
  desc  'rationale', "
    `IsLogging == true` is necessary but not sufficient. Without delivery-health surveillance, a silently-failing trail produces no archive evidence — exactly the gap an audit will surface late.
  "
  desc  'check', "
    For every trail, confirm:

    ```
    aws cloudtrail get-trail-status --name <trail-arn>
    ```

    `LatestDeliveryTime` is within the recency threshold AND `LatestDeliveryError` is empty.
  "
  desc  'fix', "
    Walk the bucket policy, KMS key policy, and bucket existence. Remediation depends on the specific error in `LatestDeliveryError`:

    - `AccessDenied` on bucket → fix bucket policy, ensure `cloudtrail.amazonaws.com` is permitted
    - `KMS.AccessDeniedException` → fix KMS key policy
    - `NoSuchBucket` → recreate bucket and re-point trail (or re-point trail to new bucket)
  "
  tag severity:              'high'
  tag severity_source:       'assessed'
  tag nist:                  ['AU-12', 'AU-9']
  tag cis_number:            'CT-1.2'
  tag cis_rid:               'CT-1.2'
  tag cis_benchmark:         'the consumer CloudTrail Baseline'
  tag cis_rule_id:           'the consumer-CT-1.2'
  tag cis_version:           '0.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag attestation_category:  'operational'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable           = applicable_partition

  impact 0.7
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')})") do
    applicable
  end

  describe aws_cloudtrail_trail_status(regions: Array(input('scan_regions')),
                                        delivery_recency_hours: input('trail_delivery_recency_hours')) do
    its('trails_with_stale_delivery') { should be_empty }
  end
end
