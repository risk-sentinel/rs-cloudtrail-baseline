# Best-effort wrapper over `organizations.list_accounts`. From the
# management account this enumerates every member account; from a
# workload account it raises AccessDenied or AWSOrganizationsNotInUse —
# we surface that case via a `connection_error` accessor so the calling
# control can fall back to attestation cleanly (per
# docs/dev/Vendored_Resource_Gaps.md §5).
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsOrganizationMemberCoverage < AwsResourceBase
  name "aws_organization_member_coverage"
  desc "Organizations member-account enumeration with connection-error accessor."
  example "
    membership = aws_organization_member_coverage
    if membership.connection_error
      describe membership do
        skip 'attestation-required: ...'
      end
    else
      describe membership do
        its('account_count') { should eq <expected> }
      end
    end
  "

  attr_reader :account_ids, :account_count, :connection_error

  def initialize(opts = {})
    super(opts)
    validate_parameters
    fetch_data
  end

  def exists?
    @connection_error.nil?
  end

  def to_s
    "AWS Organizations Member Accounts"
  end

  private

  def fetch_data
    @account_ids = []
    @account_count = 0
    @connection_error = nil
    catch_aws_errors do
      begin
        client = @aws.aws_client(::Aws::Organizations::Client)
        accounts = []
        next_token = nil
        loop do
          resp = client.list_accounts(next_token: next_token)
          accounts.concat(Array(resp.accounts).select { |a| a.status == "ACTIVE" })
          next_token = resp.next_token
          break if next_token.nil? || next_token.empty?
        end
        @account_ids = accounts.map(&:id)
        @account_count = @account_ids.length
      rescue ::Aws::Organizations::Errors::AccessDeniedException,
             ::Aws::Organizations::Errors::AWSOrganizationsNotInUseException => e
        @connection_error = e.message
      end
    end
  end
end
