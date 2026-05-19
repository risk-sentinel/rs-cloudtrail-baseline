# encoding: UTF-8

control 'C-CT-2.1' do
  title "Ensure at least one CloudTrail trail is an organization trail"
  desc  "
    An organization trail (`IsOrganizationTrail == true`) emits events from every member account in the AWS Organization to a single S3 destination, providing the centralized evidence stream that multi-account investigations and FedRAMP boundary audits depend on.

    Per-account trails alone leave gaps: any new account onboarded without explicit trail provisioning has no logging until the per-account playbook is executed. An organization trail closes that gap by default.
  "
  desc  'rationale', "
    Centralized CloudTrail aggregation is the substrate every other detection / response control sits on (GuardDuty multi-account, Security Hub findings, FedRAMP AU-6 (3) cross-account audit). Without it, evidence is fragmented per-account and onboarding is manual.
  "
  desc  'check', "
    Confirm at least one trail in `describe_trails` has `IsOrganizationTrail == true`:

    ```
    aws cloudtrail describe-trails \\
      --query 'trailList[?IsOrganizationTrail==`true`]'
    ```
  "
  desc  'fix', "
    Convert an existing multi-region trail to an organization trail (must be done from the management account):

    ```
    aws cloudtrail update-trail \\
      --name <trail-arn> \\
      --is-organization-trail
    ```

    Or create a new organization trail with `aws cloudtrail create-trail --is-organization-trail --is-multi-region-trail`.
  "
  tag severity:              'high'
  tag nist:                  ['AU-6 (3)', 'AU-12']
  tag cis_number:            'CT-2.1'
  tag cis_rid:               'CT-2.1'
  tag cis_benchmark:         'the consumer CloudTrail Baseline'
  tag cis_rule_id:           'the consumer-CT-2.1'
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
    it { should have_organization_trail }
  end
end
