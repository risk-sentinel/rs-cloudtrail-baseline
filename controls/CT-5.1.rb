# encoding: UTF-8

control 'C-CT-5.1' do
  title "Ensure CloudTrail destination buckets have Object Lock enabled"
  desc  "
    S3 Object Lock provides write-once-read-many (WORM) protection for objects in a bucket. Once enabled (and a default retention is applied), CloudTrail log files written to the bucket cannot be deleted or modified for the retention duration — even by the bucket owner or a privileged role. This is the layer beyond log-file-validation (cis-aws-foundations §4.3): validation tells you *if* tampering occurred; Object Lock prevents it.

    This control fails when any trail-destination bucket does not have Object Lock enabled.
  "
  desc  'rationale', "
    A breach involving credential theft of a privileged role can otherwise delete the audit trail in S3 along with the live evidence. Object Lock blocks that path. CIS does not cover this; the FedRAMP baseline (AU-9 (2)) treats it as the canonical tamper-resistance control.

    Note: Object Lock must be enabled at bucket creation; existing buckets cannot have it retroactively enabled. Remediation typically means provisioning a new bucket and re-pointing the trail.
  "
  desc  'check', "
    For every trail-destination bucket:

    ```
    aws s3api get-object-lock-configuration --bucket <name>
    ```

    Confirm `ObjectLockConfiguration.ObjectLockEnabled == 'Enabled'`.
  "
  desc  'fix', "
    Provision a new bucket with `--object-lock-enabled-for-bucket` at creation time, configure compliance- or governance-mode default retention, then update the trail to use the new bucket.
  "
  tag severity:              'high'
  tag severity_source:       'assessed'
  tag nist:                  ['AU-9', 'AU-9 (2)']
  tag nist_r4:               ['AU-9', 'AU-9(2)']
  tag cci:                   ['CCI-000162', 'CCI-001348']
  tag cis_number:            'CT-5.1'
  tag cis_rid:               'CT-5.1'
  tag cis_benchmark:         'the consumer CloudTrail Baseline'
  tag cis_rule_id:           'the consumer-CT-5.1'
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

  trail_status = aws_cloudtrail_trail_status(regions: Array(input('scan_regions')),
                                              delivery_recency_hours: input('trail_delivery_recency_hours'))
  buckets = trail_status.trail_buckets

  if buckets.empty?
    describe 'Trail-bucket Object Lock (no trails configured)' do
      skip 'no visible trails — nothing to inspect.'
    end
  else
    buckets.each do |bucket|
      describe aws_s3_bucket_features(bucket_name: bucket) do
        it { should have_object_lock_enabled }
      end
    end
  end
end
