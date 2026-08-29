# encoding: UTF-8

control 'C-CT-4.1' do
  title "Ensure every CloudTrail trail forwards to CloudWatch Logs"
  desc  "
    A trail that writes only to S3 produces archive evidence but not real-time signal. Forwarding events to CloudWatch Logs is the substrate cis-aws-foundations §5 metric filters depend on (root-login, IAM-policy-change, etc.) — the alerting layer of the audit chain.

    A trail's CWL forwarding is configured by `CloudWatchLogsLogGroupArn` + `CloudWatchLogsRoleArn` from `describe_trails`. Both must be populated; either nil/empty disables forwarding for that trail.

    This control fails when any visible trail is missing either field.
  "
  desc  'rationale', "
    Without CWL forwarding, the §5 metric filters never fire — they read from the log group, not S3. A trail config that satisfies §4 (writes to S3, encrypted, validated) can still leave §5 silently inoperative if CWL forwarding is incomplete.
  "
  desc  'check', "
    For every trail in `describe_trails`, confirm:

    - `CloudWatchLogsLogGroupArn` is non-empty
    - `CloudWatchLogsRoleArn` is non-empty
  "
  desc  'fix', "
    Configure CWL forwarding:

    ```
    aws cloudtrail update-trail \\
      --name <trail-arn> \\
      --cloud-watch-logs-log-group-arn <log-group-arn> \\
      --cloud-watch-logs-role-arn <role-arn>
    ```

    Ensure the role has the `CloudTrail_CloudWatchLogs_Role` permissions for `logs:CreateLogStream` and `logs:PutLogEvents` on the destination log group.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AU-6 (1)', 'SI-4 (5)']
  tag cis_number:            'CT-4.1'
  tag cis_rid:               'CT-4.1'
  tag cis_benchmark:         'the consumer CloudTrail Baseline'
  tag cis_rule_id:           'the consumer-CT-4.1'
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
    its('trails_missing_cwl_destination') { should be_empty }
  end
end
