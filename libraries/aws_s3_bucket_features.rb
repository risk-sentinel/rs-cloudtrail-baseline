# Composite read-only S3-bucket resource exposing the three feature
# surfaces Theme 5 needs: Object Lock configuration, the bucket policy
# document (raw + parsed), and lifecycle rules. Each backs a separate
# SDK call; rolling them into one resource keeps the per-bucket fetch
# cost bounded (3 calls per bucket regardless of how many controls
# inspect it) and avoids cross-resource result-cache divergence.
#
# Each accessor's underlying call may return AccessDenied or a service-
# specific NoSuchConfiguration; we catch and translate to the
# corresponding "absent" result rather than propagating exceptions to
# describe blocks.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsS3BucketFeatures < AwsResourceBase
  name "aws_s3_bucket_features"
  desc "Composite resource exposing Object Lock, bucket policy, lifecycle for an S3 bucket."
  example "
    describe aws_s3_bucket_features(bucket_name: 'my-trail-archive') do
      it { should have_object_lock_enabled }
      it { should deny_non_tls_put }
      its('days_to_archive_transition') { should be <= 90 }
    end
  "

  GLACIER_STORAGE_CLASSES = %w[GLACIER GLACIER_IR DEEP_ARCHIVE].freeze

  attr_reader :bucket_name,
              :object_lock_status,
              :bucket_policy_doc,
              :lifecycle_rules,
              :days_to_archive_transition

  def initialize(opts = {})
    opts = { bucket_name: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: [:bucket_name])
    @bucket_name = opts[:bucket_name].to_s
    fetch_object_lock
    fetch_bucket_policy
    fetch_lifecycle
  end

  def exists?
    !@bucket_name.empty?
  end

  def has_object_lock_enabled?
    @object_lock_status == "Enabled"
  end

  # Returns true if the parsed bucket policy contains a Deny statement
  # that targets s3:PutObject (or all s3:* / *) on this bucket / its
  # objects, with a `Bool` Condition asserting `aws:SecureTransport`
  # equals "false". Permissive on the action surface (anything that
  # *includes* PutObject counts) but strict on the condition shape.
  def deny_non_tls_put?
    statements = Array(@bucket_policy_doc&.dig("Statement"))
    statements.any? { |s| tls_deny_statement?(s) }
  end

  def to_s
    "AWS S3 Bucket Features '#{@bucket_name}'"
  end

  private

  def fetch_object_lock
    @object_lock_status = nil
    catch_aws_errors do
      begin
        resp = @aws.storage_client.get_object_lock_configuration(bucket: @bucket_name)
        @object_lock_status = resp.object_lock_configuration&.object_lock_enabled
      rescue ::Aws::S3::Errors::ObjectLockConfigurationNotFoundError
        @object_lock_status = nil
      end
    end
  end

  def fetch_bucket_policy
    @bucket_policy_doc = nil
    catch_aws_errors do
      begin
        resp = @aws.storage_client.get_bucket_policy(bucket: @bucket_name)
        require "json"
        @bucket_policy_doc = JSON.parse(resp.policy.to_s)
      rescue ::Aws::S3::Errors::NoSuchBucketPolicy, JSON::ParserError
        @bucket_policy_doc = nil
      end
    end
  end

  def fetch_lifecycle
    @lifecycle_rules = []
    @days_to_archive_transition = nil
    catch_aws_errors do
      begin
        resp = @aws.storage_client.get_bucket_lifecycle_configuration(bucket: @bucket_name)
        @lifecycle_rules = Array(resp.rules).map do |r|
          {
            id:          r.id,
            status:      r.status,
            transitions: Array(r.transitions).map { |t| { days: t.days, storage_class: t.storage_class } },
          }
        end
        @days_to_archive_transition = compute_days_to_archive_transition
      rescue ::Aws::S3::Errors::NoSuchLifecycleConfiguration
        @lifecycle_rules = []
        @days_to_archive_transition = nil
      end
    end
  end

  def compute_days_to_archive_transition
    candidates = @lifecycle_rules
                   .select { |r| r[:status] == "Enabled" }
                   .flat_map { |r| r[:transitions] }
                   .select { |t| GLACIER_STORAGE_CLASSES.include?(t[:storage_class]) }
                   .map { |t| t[:days] }
                   .compact
    candidates.min
  end

  def tls_deny_statement?(statement)
    return false unless statement.is_a?(Hash)
    return false unless statement["Effect"] == "Deny"
    return false unless action_includes_put_object?(statement["Action"])
    condition = statement["Condition"]
    return false unless condition.is_a?(Hash)
    bool_block = condition["Bool"] || condition["BoolIfExists"]
    return false unless bool_block.is_a?(Hash)
    val = bool_block["aws:SecureTransport"]
    val.to_s.downcase == "false" || (val.is_a?(Array) && val.map(&:to_s).map(&:downcase).include?("false"))
  end

  def action_includes_put_object?(action)
    actions = Array(action).map(&:to_s)
    actions.any? { |a| a == "*" || a == "s3:*" || a == "s3:PutObject" || a.start_with?("s3:Put") }
  end
end
