# Trail-health enumeration: per-trail get_trail_status output joined to
# describe_trails so consumers can assert is_logging + delivery freshness
# in one place. Vendored aws_cloudtrail_trail does not expose these
# fields. Depends on `_aws_backend_bootstrap.rb` having loaded first.
#
# Why region-walking with direct Aws::CloudTrail::Client.new(region:)
# rather than @aws.cloudtrail_client: train-aws's cloudtrail_client is
# bound to a single region; multi-region trail enumeration needs sweeps
# per region (single-region trails appear in describe_trails only from
# their home region). Same pattern as
# cis-aws-foundations/libraries/aws_cloudtrail_event_selectors.rb.
#
# Filterable per-trail rows + top-level violation arrays keyed off the
# delivery-recency input. Controls call into either the violations array
# (Theme 1.1 / 1.3) or filter rows (Theme 1.2 / 4.3).
#
# Context: docs/dev/Vendored_Resource_Gaps.md.

class AwsCloudtrailTrailStatus < AwsResourceBase
  name "aws_cloudtrail_trail_status"
  desc "Per-trail get_trail_status fields (is_logging, delivery times, errors)."
  example "
    describe aws_cloudtrail_trail_status(regions: Array(input('scan_regions')),
                                          delivery_recency_hours: input('trail_delivery_recency_hours')) do
      its('trails_not_logging')      { should be_empty }
      its('trails_with_stale_delivery') { should be_empty }
      its('trails_with_digest_errors')  { should be_empty }
    end
  "

  attr_reader :table

  FilterTable.create
    .register_column(:trail_arns,                              field: :trail_arn)
    .register_column(:trail_names,                             field: :trail_name)
    .register_column(:home_regions,                            field: :home_region)
    .register_column(:is_multi_region,                         field: :is_multi_region)
    .register_column(:is_organization,                         field: :is_organization)
    .register_column(:is_logging,                              field: :is_logging)
    .register_column(:latest_delivery_times,                   field: :latest_delivery_time)
    .register_column(:latest_delivery_errors,                  field: :latest_delivery_error)
    .register_column(:latest_digest_delivery_errors,           field: :latest_digest_delivery_error)
    .register_column(:latest_cloud_watch_logs_delivery_times,  field: :latest_cloud_watch_logs_delivery_time)
    .register_column(:latest_cloud_watch_logs_delivery_errors, field: :latest_cloud_watch_logs_delivery_error)
    .install_filter_methods_on_resource(self, :table)

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    @recency_seconds = (opts.delete(:delivery_recency_hours) || 24).to_i * 3600
    super(opts)
    validate_parameters
    @all_regions = region_override.empty? ? fetch_default_regions : region_override
    @table = fetch_data
  end

  def exists?
    !@table.empty?
  end

  def trails_not_logging
    @table.reject { |row| row[:is_logging] }.map { |row| row[:trail_arn] }
  end

  def trails_with_stale_delivery
    cutoff = Time.now - @recency_seconds
    @table.select do |row|
      row[:latest_delivery_time].nil? ||
        row[:latest_delivery_time] < cutoff ||
        !row[:latest_delivery_error].to_s.empty?
    end.map { |row| row[:trail_arn] }
  end

  def trails_with_digest_errors
    @table.reject { |row| row[:latest_digest_delivery_error].to_s.empty? }
          .map { |row| row[:trail_arn] }
  end

  def trails_with_stale_cwl_delivery
    cutoff = Time.now - @recency_seconds
    @table.select do |row|
      row[:latest_cloud_watch_logs_delivery_time].nil? ||
        row[:latest_cloud_watch_logs_delivery_time] < cutoff ||
        !row[:latest_cloud_watch_logs_delivery_error].to_s.empty?
    end.map { |row| row[:trail_arn] }
  end

  def organization_trails
    @table.select { |row| row[:is_organization] }
  end

  def has_organization_trail?
    !organization_trails.empty?
  end

  def organization_trail_buckets
    organization_trails.map { |row| row[:s3_bucket_name] }.compact.uniq
  end

  # Every distinct trail-destination S3 bucket name in the visible trail
  # set (org and per-account). Theme 5 iterates this for tamper-resistance
  # checks (Object Lock, TLS-deny, lifecycle).
  def trail_buckets
    @table.map { |row| row[:s3_bucket_name] }.compact.reject(&:empty?).uniq
  end

  def trails_with_unapproved_buckets(approved_buckets)
    allowed = Array(approved_buckets).map(&:to_s)
    organization_trails.reject { |row| allowed.include?(row[:s3_bucket_name].to_s) }
                       .map { |row| { trail_arn: row[:trail_arn], bucket: row[:s3_bucket_name] } }
  end

  def trails_missing_cwl_destination
    @table.select { |row| row[:cwl_log_group].to_s.empty? || row[:cwl_role_arn].to_s.empty? }
          .map { |row| row[:trail_arn] }
  end

  # Returns the unique CloudWatch Logs log-group ARNs across all trails
  # whose CWL destination is configured. Theme 4 consumes this.
  def configured_cwl_log_group_arns
    @table.map { |row| row[:cwl_log_group] }.compact.reject(&:empty?).uniq
  end

  def to_s
    "CloudTrail Trail Status"
  end

  private

  def fetch_data
    rows = []
    enumerate_trails.each do |trail|
      status = fetch_status(trail)
      rows << trail.merge(status) if status
    end
    rows
  end

  def enumerate_trails
    trails = []
    seen = {}
    @all_regions.each do |region|
      begin
        client = ::Aws::CloudTrail::Client.new(region: region)
        resp = client.describe_trails
        Array(resp.trail_list).each do |t|
          next if seen.key?(t.trail_arn)
          seen[t.trail_arn] = true
          trails << {
            trail_arn:        t.trail_arn,
            trail_name:       t.name,
            home_region:      t.home_region,
            is_multi_region:  t.is_multi_region_trail,
            is_organization:  t.is_organization_trail,
            s3_bucket_name:   t.s3_bucket_name,
            cwl_log_group:    t.cloud_watch_logs_log_group_arn,
            cwl_role_arn:     t.cloud_watch_logs_role_arn,
          }
        end
      rescue ::Aws::Errors::ServiceError => e
        Inspec::Log.warn("aws_cloudtrail_trail_status: describe_trails in #{region} failed: #{e.message}")
      end
    end
    trails
  end

  def fetch_status(trail)
    client = ::Aws::CloudTrail::Client.new(region: trail[:home_region])
    resp = client.get_trail_status(name: trail[:trail_arn])
    {
      is_logging:                              resp.is_logging,
      latest_delivery_time:                    resp.latest_delivery_time,
      latest_delivery_error:                   resp.latest_delivery_error,
      latest_digest_delivery_error:            resp.latest_digest_delivery_error,
      latest_cloud_watch_logs_delivery_time:   resp.latest_cloud_watch_logs_delivery_time,
      latest_cloud_watch_logs_delivery_error:  resp.latest_cloud_watch_logs_delivery_error,
    }
  rescue ::Aws::Errors::ServiceError => e
    Inspec::Log.warn("aws_cloudtrail_trail_status: get_trail_status(#{trail[:trail_arn]}) failed: #{e.message}")
    nil
  end

  def fetch_default_regions
    regions = []
    catch_aws_errors do
      regions = @aws.compute_client.describe_regions.regions.map(&:region_name)
    end
    regions
  end
end
