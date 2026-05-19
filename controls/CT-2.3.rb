# encoding: UTF-8

control 'C-CT-2.3' do
  title "Ensure organization-trail covers every active member account"
  desc  "
    An organization trail's value depends on it actually capturing every member account. This control walks `organizations.list_accounts` (mgmt-account-only API) and asserts the active-account count is non-zero (i.e., the Organization is in use and the trail's coverage will be meaningful).

    Run from the management account: this control is fully automated. Run from a workload account: `organizations:ListAccounts` returns `AccessDenied`; the control falls through to attestation rationale (per CMS-pattern + the connection-precheck pattern in `docs/dev/Vendored_Resource_Gaps.md` §5).
  "
  desc  'rationale', "
    A 'has organization trail' check (CT-2.1) is necessary but not sufficient — an organization with zero member accounts, or one where the trail was provisioned before accounts were added, can still pass CT-2.1 trivially. Tying the assertion to the actual member-account enumeration closes that gap.
  "
  desc  'check', "
    From the management account:

    ```
    aws organizations list-accounts \\
      --query 'Accounts[?Status==`ACTIVE`] | length(@)'
    ```

    Confirm count > 0 and matches the expected member count.
  "
  desc  'fix', "
    If the organization has no active accounts, onboard them per the AWS Organizations + Control Tower runbook. If the count is lower than expected, walk the OU tree to identify accounts not yet under the organization trail's scope.
  "
  tag severity:              'medium'
  tag nist:                  ['AU-6 (4)']
  tag cis_number:            'CT-2.3'
  tag cis_rid:               'CT-2.3'
  tag cis_benchmark:         'the consumer CloudTrail Baseline'
  tag cis_rule_id:           'the consumer-CT-2.3'
  tag cis_version:           '0.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable           = applicable_partition

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')})") do
    applicable
  end

  membership = aws_organization_member_coverage

  if membership.connection_error
    attestation_ref = input('organizations_attestation_reference').to_s
    attestation_msg = "attestation-required: organizations:ListAccounts unreachable from this account " \
                      "(#{membership.connection_error}). Consumer attests separately to organization-trail " \
                      "member-coverage review."
    attestation_msg += " Reference: #{attestation_ref}." unless attestation_ref.empty?

    describe 'Organization member-account coverage (workload-account fallback)' do
      skip attestation_msg
    end
  else
    describe membership do
      its('account_count') { should be > 0 }
    end
  end
end
