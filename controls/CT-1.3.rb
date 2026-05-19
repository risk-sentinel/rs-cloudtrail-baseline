# encoding: UTF-8

control 'C-CT-1.3' do
  title "Ensure CloudTrail digest delivery is error-free (validates §4.3 chain)"
  desc  "
    cis-aws-foundations §4.3 verifies that `LogFileValidationEnabled == true`. With log file validation enabled, CloudTrail writes a digest file once per hour to the same S3 bucket; the digest cryptographically chains the previous digests so that any deletion or modification breaks the chain.

    `LatestDigestDeliveryError` from `get_trail_status` reports failures of that digest delivery. A non-empty value means the validation chain is broken — §4.3 reports green but the validation feature is silently inoperative.

    This control fails when any trail has a non-empty `LatestDigestDeliveryError`.
  "
  desc  'rationale', "
    Log file validation is the tamper-evidence mechanism CloudTrail provides. If the digest chain is broken, an attacker (or a bug) can modify or delete log files without detection. Trusting §4.3 alone gives a false-positive — the feature is enabled but not working.
  "
  desc  'check', "
    For every trail, confirm:

    ```
    aws cloudtrail get-trail-status --name <trail-arn>
    ```

    `LatestDigestDeliveryError` is empty / null.
  "
  desc  'fix', "
    Common causes:

    - Bucket policy denies the digest-delivery principal
    - KMS key policy denies digest encryption
    - Trail's log-file-validation flag was disabled then re-enabled mid-cycle (chain breaks)
  "
  tag severity:              'medium'
  tag nist:                  ['AU-9', 'AU-10']
  tag cis_number:            'CT-1.3'
  tag cis_rid:               'CT-1.3'
  tag cis_benchmark:         'the consumer CloudTrail Baseline'
  tag cis_rule_id:           'the consumer-CT-1.3'
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
    its('trails_with_digest_errors') { should be_empty }
  end
end
