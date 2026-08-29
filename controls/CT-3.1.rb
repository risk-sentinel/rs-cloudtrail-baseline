# encoding: UTF-8

control 'C-CT-3.1' do
  title "Ensure at least one trail captures Lambda invoke data events"
  desc  "
    cis-aws-foundations §4.8 / §4.9 covers S3 object-level read/write data events. Lambda function invocations are the parallel surface for serverless workloads — without `AWS::Lambda::Function` data events on a trail, every invocation of every Lambda runs without an audit-trail entry; only the management-events around Lambda configuration get logged.

    This control fails when no visible trail captures Lambda data events.
  "
  desc  'rationale', "
    Serverless workloads execute on Lambda; without invoke-data-event logging, FedRAMP audit-trail evidence (AU-2 / AU-12) is incomplete for that surface. CIS does not cover this; the Well-Architected Security pillar treats it as best practice.
  "
  desc  'check', "
    For every trail, walk `get_event_selectors` output looking for either:

    - a classic `event_selectors[].data_resources[]` entry with `type == 'AWS::Lambda::Function'`
    - an advanced selector with `eventCategory == 'Data'` AND `resources.type == 'AWS::Lambda::Function'`
  "
  desc  'fix', "
    Update the trail to capture Lambda data events:

    ```
    aws cloudtrail put-event-selectors \\
      --trail-name <trail-arn> \\
      --advanced-event-selectors \\
        '[{\"Name\":\"Lambda invocations\",\"FieldSelectors\":[{\"Field\":\"eventCategory\",\"Equals\":[\"Data\"]},{\"Field\":\"resources.type\",\"Equals\":[\"AWS::Lambda::Function\"]}]}]'
    ```

    Note Lambda data events incur per-invocation logging cost; for large fleets, scope to specific function ARNs rather than the wildcard.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AU-12', 'AU-2']
  tag nist_r4:               ['AU-12', 'AU-2']
  tag cci:                   ['CCI-000123', 'CCI-000169']
  tag cis_number:            'CT-3.1'
  tag cis_rid:               'CT-3.1'
  tag cis_benchmark:         'the consumer CloudTrail Baseline'
  tag cis_rule_id:           'the consumer-CT-3.1'
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

  # `should be_log_lambda_data_events` (with `be_` prefix) is the
  # idiomatic predicate-matcher form — RSpec resolves it to
  # `subject.log_lambda_data_events?` (the predicate method defined on
  # the resource). Bare `should log_lambda_data_events` (without `be_`)
  # is interpreted as a custom matcher name and fails at exec time
  # with "undefined local variable or method 'log_lambda_data_events'".
  # See memory file feedback_inspec_predicate_matchers.md.
  describe aws_cloudtrail_data_event_coverage(regions: Array(input('scan_regions'))) do
    it { should be_log_lambda_data_events }
  end
end
