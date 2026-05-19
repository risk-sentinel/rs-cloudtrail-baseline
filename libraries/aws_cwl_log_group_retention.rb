# Per-log-group retention check for CloudWatch Logs. Resolves the
# log-group ARN reference from a CloudTrail trail (e.g.,
# "arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail/DefaultLogGroup:*")
# down to the log-group name + region, then calls describe_log_groups
# with that name as a prefix to read `retention_in_days`.
#
# AWS surfaces "Never expire" as a nil retention_in_days on the log
# group, which the consumer may want to accept regardless of any minimum
# threshold. The control body decides; this resource just exposes the
# raw value via `retention_days` (Integer or nil).
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsCwlLogGroupRetention < AwsResourceBase
  name "aws_cwl_log_group_retention"
  desc "CloudWatch Logs log-group retention (resolves from trail's log-group ARN)."
  example "
    describe aws_cwl_log_group_retention(log_group_arn: 'arn:aws:logs:us-east-1:123:log-group:foo:*') do
      it { should exist }
      its('retention_days') { should be >= 365 }
    end
  "

  attr_reader :log_group_name, :region, :retention_days

  def initialize(opts = {})
    opts = { log_group_arn: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: [:log_group_arn])
    @log_group_arn = opts[:log_group_arn].to_s
    parse_arn
    fetch_data
  end

  def exists?
    @exists == true
  end

  def never_expires?
    @retention_days.nil? && @exists
  end

  def to_s
    "AWS CWL Log Group '#{@log_group_name}'"
  end

  private

  # ARN shape: arn:<partition>:logs:<region>:<acct>:log-group:<name>:*
  # Splitting on ':' is safe here — `:log-group:` is the marker, and
  # anything after it is the name (which itself can contain '/' but not
  # ':' in valid AWS naming).
  def parse_arn
    parts = @log_group_arn.split(":")
    @region = parts[3]
    lg_index = parts.index("log-group")
    @log_group_name = parts[(lg_index + 1)..].join(":").sub(/:\*$/, "") if lg_index
  end

  def fetch_data
    @exists = false
    return if @log_group_name.nil? || @log_group_name.empty? || @region.nil?
    catch_aws_errors do
      client = ::Aws::CloudWatchLogs::Client.new(region: @region)
      resp = client.describe_log_groups(log_group_name_prefix: @log_group_name)
      group = Array(resp.log_groups).find { |g| g.log_group_name == @log_group_name }
      if group
        @exists = true
        @retention_days = group.retention_in_days
      end
    end
  end
end
