# encoding: UTF-8

control 'C-CT-5.3' do
  title "Ensure CloudTrail buckets transition to Glacier within threshold"
  desc  "
    Long-term audit-log retention is cheaper in S3 Glacier / Glacier Instant Retrieval / Deep Archive than in S3 Standard, but only if a lifecycle rule transitions logs there. The bucket must have an Enabled lifecycle rule whose Transition action moves objects to one of `GLACIER`, `GLACIER_IR`, or `DEEP_ARCHIVE` within `trail_bucket_glacier_transition_days` days (default 90).

    This control fails when no Enabled lifecycle rule has a qualifying transition, or when the smallest-day transition exceeds the threshold.
  "
  desc  'rationale', "
    Cost is the practical lever — a trail bucket with no lifecycle accumulates uncapped Standard-tier storage. Beyond cost, codifying the transition demonstrates the consumer has thought about long-term retention separate from the §4.6 KMS-rotation question, which is also retention-adjacent but distinct.
  "
  desc  'check', "
    ```
    aws s3api get-bucket-lifecycle-configuration --bucket <name>
    ```

    Confirm at least one Enabled rule has a Transition with `StorageClass` in `[GLACIER, GLACIER_IR, DEEP_ARCHIVE]` and `Days` <= threshold.
  "
  desc  'fix', "
    Add a lifecycle rule transitioning objects to Glacier:

    ```
    aws s3api put-bucket-lifecycle-configuration \\
      --bucket <name> \\
      --lifecycle-configuration '{
        \"Rules\":[{
          \"ID\":\"archive-after-90d\",
          \"Status\":\"Enabled\",
          \"Filter\":{},
          \"Transitions\":[{
            \"Days\":90,
            \"StorageClass\":\"GLACIER\"
          }]
        }]
      }'
    ```
  "
  tag severity:              'low'
  tag severity_source:       'assessed'
  tag nist:                  ['AU-11', 'CP-9']
  tag cis_number:            'CT-5.3'
  tag cis_rid:               'CT-5.3'
  tag cis_benchmark:         'the consumer CloudTrail Baseline'
  tag cis_rule_id:           'the consumer-CT-5.3'
  tag cis_version:           '0.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag attestation_category:  'operational'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable           = applicable_partition

  impact 0.3
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')})") do
    applicable
  end

  threshold = Integer(input('trail_bucket_glacier_transition_days'))
  trail_status = aws_cloudtrail_trail_status(regions: Array(input('scan_regions')),
                                              delivery_recency_hours: input('trail_delivery_recency_hours'))
  buckets = trail_status.trail_buckets

  if buckets.empty?
    describe 'Trail-bucket lifecycle (no trails configured)' do
      skip 'no visible trails — nothing to inspect.'
    end
  else
    buckets.each do |bucket|
      describe aws_s3_bucket_features(bucket_name: bucket) do
        it "transitions to GLACIER / GLACIER_IR / DEEP_ARCHIVE within #{threshold} days (bucket: #{bucket})" do
          days = subject.days_to_archive_transition
          expect(days).not_to be_nil
          expect(days).to be <= threshold
        end
      end
    end
  end
end
