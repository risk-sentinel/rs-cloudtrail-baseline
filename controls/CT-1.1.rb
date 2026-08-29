# encoding: UTF-8

control 'C-CT-1.1' do
  title "Ensure CloudTrail trails are actively logging (`IsLogging == true`)"
  desc  "
    A CloudTrail trail can exist as a configured resource but be in a stopped state — `StopLogging` was called against it, intentionally or via a policy regression. cis-aws-foundations §4.2 confirms that a trail exists; this control confirms that every trail is actually emitting events.
  "
  desc  'rationale', "
    Without active logging, downstream evidence (S3 archive, CloudWatch Logs, metric filters, GuardDuty) goes silent — even though the trail still appears in the console. Detecting this drift requires `cloudtrail.get_trail_status` per trail; `describe_trails` alone does not surface it.
  "
  desc  'check', "
    For every trail visible in `describe_trails` across every active region, confirm that `cloudtrail.get_trail_status(name: <trail-arn>).is_logging == true`.
  "
  desc  'fix', "
    Re-enable logging on the affected trails:

    ```
    aws cloudtrail start-logging --name <trail-arn>
    ```

    Then investigate root cause: review CloudTrail event history for `StopLogging` calls, the principal that issued them, and whether the IAM policy permitting `cloudtrail:StopLogging` is intentional. CIS 5.4 (Stop / Start logging metric filter) provides the alerting tie-in.
  "
  tag severity:              'high'
  tag severity_source:       'assessed'
  tag nist:                  ['AU-12']
  tag ksi:                   ['KSI-MLA-LET']
  tag nist_r4:               ['AU-12']
  tag cci:                   ['CCI-000169']
  tag cis_number:            'CT-1.1'
  tag cis_rid:               'CT-1.1'
  tag cis_benchmark:         'the consumer CloudTrail Baseline'
  tag cis_rule_id:           'the consumer-CT-1.1'
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
    its('trails_not_logging') { should be_empty }
  end
end
