# encoding: UTF-8

control 'C-CT-3.2' do
  title "Ensure S3 data events cover the consumer-supplied required-bucket-ARN list"
  desc  "
    cis-aws-foundations §4.8 / §4.9 asserts that some trail captures S3 object-level events globally (any bucket). For the consumer's compliance posture, certain buckets — evidence stores, customer-data buckets, audit log archives — must have object-level events captured specifically. This control fails when any bucket in the required list is not covered by a trail's data-event selectors (per-bucket ARN match, or covered by the wildcard `arn:aws:s3:::`).
  "
  desc  'rationale', "
    The §4 wildcard check answers 'is there any S3 logging at all?'. The §4 check passes if a single dev bucket has logging enabled, which is necessary but not sufficient — it does not assert that the *audit-relevant* buckets are covered.

    Empty input (`required_data_event_bucket_arns: []`) skips with attestation rationale, leaving the question to a separate consumer review.
  "
  desc  'check', "
    For every required bucket ARN, confirm at least one trail has either:

    - per-bucket ARN coverage in classic `data_resources[]` with `type == 'AWS::S3::Object'` and the bucket ARN (or an arn-prefix matching it) in `values`
    - advanced-selector with `resources.type == 'AWS::S3::Object'` and either `resources.ARN.equals` or `resources.ARN.starts_with` matching the bucket
    - global wildcard coverage (`arn:aws:s3:::` covers every bucket)
  "
  desc  'fix', "
    Add the bucket to an existing trail's selectors, or create a dedicated trail for the audit-relevant bucket set. Example:

    ```
    aws cloudtrail put-event-selectors \\
      --trail-name <trail-arn> \\
      --event-selectors \\
        '[{\"ReadWriteType\":\"All\",\"IncludeManagementEvents\":true,\"DataResources\":[{\"Type\":\"AWS::S3::Object\",\"Values\":[\"arn:aws:s3:::sparc-prod-evidence/\"]}]}]'
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AU-12 (1)', 'AC-3']
  tag cis_number:            'CT-3.2'
  tag cis_rid:               'CT-3.2'
  tag cis_benchmark:         'the consumer CloudTrail Baseline'
  tag cis_rule_id:           'the consumer-CT-3.2'
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

  required = Array(input('required_data_event_bucket_arns'))

  if required.empty?
    describe 'S3 data event scoping (no required-bucket list)' do
      skip 'attestation-required: required_data_event_bucket_arns is empty — ' \
           'consumer attests separately to which buckets require object-level event logging. ' \
           'Populate the input with bucket ARNs (e.g., arn:aws:s3:::sparc-prod-evidence) to enforce.'
    end
  else
    describe aws_cloudtrail_data_event_coverage(regions: Array(input('scan_regions')),
                                                 required_s3_bucket_arns: required) do
      its('missing_s3_bucket_arns') { should be_empty }
    end
  end
end
