# encoding: UTF-8

control 'C-CT-2.2' do
  title "Ensure organization-trail destination buckets are in approved log-archive allowlist"
  desc  "
    The S3 destination of an organization trail is the bucket that holds the raw evidence stream for every member account. Best practice (FedRAMP-aligned, AWS Well-Architected Security pillar) is to put that bucket in a dedicated security / log-archive account, not in the management account or any workload account.

    This control fails if any organization trail's destination bucket is not in the consumer-supplied `approved_trail_buckets` allowlist. Empty input skips with attestation rationale (consumer attests separately to the bucket-provenance review).
  "
  desc  'rationale', "
    A trail bucket living in a workload account is one bucket-policy regression away from being deleted, made public, or having log-delivery permissions stripped. Pinning it to a known security-account bucket allowlist enforces the boundary the architecture intended.
  "
  desc  'check', "
    For each organization trail returned by `describe_trails`, confirm `S3BucketName` is in the consumer's approved allowlist (security-account log archive bucket(s)).
  "
  desc  'fix', "
    Re-point the trail to the approved security-account bucket:

    ```
    aws cloudtrail update-trail \\
      --name <trail-arn> \\
      --s3-bucket-name <approved-bucket>
    ```

    Then update the bucket's policy to permit `cloudtrail.amazonaws.com:PutObject` for the new trail's source ARN.
  "
  tag severity:              'medium'
  tag nist:                  ['AU-9 (2)']
  tag cis_number:            'CT-2.2'
  tag cis_rid:               'CT-2.2'
  tag cis_benchmark:         'the consumer CloudTrail Baseline'
  tag cis_rule_id:           'the consumer-CT-2.2'
  tag cis_version:           '0.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag attestation_category:  'policy'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable           = applicable_partition

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')})") do
    applicable
  end

  approved = Array(input('approved_trail_buckets'))

  if approved.empty?
    describe 'Organization-trail bucket allowlist (no scope)' do
      skip 'attestation-required: no buckets declared in approved_trail_buckets — ' \
           'consumer attests separately that the trail-destination bucket review has been performed. ' \
           'Populate approved_trail_buckets with the security-account log-archive bucket name(s) to enforce.'
    end
  else
    trail_status = aws_cloudtrail_trail_status(regions: Array(input('scan_regions')),
                                                delivery_recency_hours: input('trail_delivery_recency_hours'))
    describe 'Organization-trail destination buckets vs. approved allowlist' do
      subject { trail_status.trails_with_unapproved_buckets(approved) }
      it { should be_empty }
    end
  end
end
