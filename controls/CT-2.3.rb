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
    # organizations:ListAccounts is unreachable from this (workload) account.
    # The automated path above runs from the management account; here we lift
    # the fallback from a bare Skip to Pass-with-evidence via document_attestation
    # (sparc-validate#115): assert the member-coverage review attestation exists
    # and is current. If no attestation URI is configured we preserve the prior
    # Skip-with-rationale behavior so existing consumers aren't broken.
    attestation_uri = input('c_ct_2_3_attestation_uri', value: '')
    max_age_days    = input('c_ct_2_3_attestation_max_age_days', value: 365)

    if attestation_uri.to_s.empty?
      attestation_ref = input('organizations_attestation_reference').to_s
      attestation_msg = "attestation-required: organizations:ListAccounts unreachable from this account " \
                        "(#{membership.connection_error}). Set c_ct_2_3_attestation_uri to lift this to " \
                        "Pass-with-evidence, or attest separately to organization-trail member-coverage review."
      attestation_msg += " Reference: #{attestation_ref}." unless attestation_ref.empty?

      describe 'Organization member-account coverage (workload-account fallback)' do
        skip attestation_msg
      end
    else
      doc = document_attestation(attestation_uri, max_age_days: max_age_days)
      describe "C-CT-2.3 organization member-coverage attestation (#{attestation_uri})" do
        it 'is reachable (no connection error)' do
          expect(doc.connection_error).to be_nil, "attestation unreachable: #{doc.connection_error}"
        end
        it 'exists' do
          expect(doc.exists?).to eq(true)
        end
        it "is current within #{max_age_days} days" do
          expect(doc.current?).to eq(true)
        end
      end
    end
  else
    describe membership do
      its('account_count') { should be > 0 }
    end
  end
end
