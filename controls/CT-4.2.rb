# encoding: UTF-8

control 'C-CT-4.2' do
  title "Ensure CloudTrail's CloudWatch Logs log groups meet retention floor"
  desc  "
    The CWL log group destinations referenced by CloudTrail trails must retain events long enough for the consumer's audit window. Default `cwl_retention_min_days` is 365 (FedRAMP-aligned baseline for AU-11). Log groups configured with 'Never expire' (no `retention_in_days`) are accepted regardless of the threshold.

    This control fails when any trail's CWL log group has a finite retention shorter than `cwl_retention_min_days`. A retention floor of 0 disables the floor entirely (any positive retention is accepted).
  "
  desc  'rationale', "
    The retention setting is independent of the trail's S3 archive (which keeps events indefinitely until lifecycle ages them out). CWL is the live-query layer; if it expires events sooner than the audit window, FedRAMP audit-trail evidence (AU-11) is incomplete for that surface.
  "
  desc  'check', "
    For every trail's CWL destination log group:

    ```
    aws logs describe-log-groups \\
      --log-group-name-prefix <log-group-name> \\
      --query 'logGroups[?logGroupName==`<log-group-name>`].retentionInDays'
    ```

    Confirm the value is either null (Never expire) or >= the threshold.
  "
  desc  'fix', "
    Increase retention:

    ```
    aws logs put-retention-policy \\
      --log-group-name <name> \\
      --retention-in-days 365
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AU-11']
  tag cis_number:            'CT-4.2'
  tag cis_rid:               'CT-4.2'
  tag cis_benchmark:         'the consumer CloudTrail Baseline'
  tag cis_rule_id:           'the consumer-CT-4.2'
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

  threshold = Integer(input('cwl_retention_min_days'))
  trail_status = aws_cloudtrail_trail_status(regions: Array(input('scan_regions')),
                                              delivery_recency_hours: input('trail_delivery_recency_hours'))
  configured_arns = trail_status.configured_cwl_log_group_arns

  if configured_arns.empty?
    describe 'CloudWatch Logs retention (no trail forwards to CWL)' do
      skip 'no trails configured with a CloudWatch Logs destination — C-CT-4.1 surfaces this; nothing to check here.'
    end
  else
    configured_arns.each do |arn|
      describe aws_cwl_log_group_retention(log_group_arn: arn) do
        it { should exist }
        # Accept either "Never expire" or retention >= threshold.
        # Use a custom matcher via subject so we honor both branches.
        it "retains events for at least #{threshold} days (or never expires)" do
          retention = subject.retention_days
          expect(retention.nil? || retention >= threshold).to eq(true)
        end
      end
    end
  end
end
