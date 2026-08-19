# Cross-trail data-event coverage scanner. Joins describe_trails ×
# get_event_selectors and exposes whether the visible trail set captures:
#   - Lambda invoke data events (any AWS::Lambda::Function selector)
#   - per-bucket S3 data events for a consumer-supplied required-ARN list
#
# Why a new resource alongside cis-aws-foundations'
# aws_cloudtrail_event_selectors: that helper is purpose-built for the
# §4.8 / §4.9 wildcard-S3 questions ("does any trail capture S3 reads /
# writes globally?"). For Theme 3 we need to ask the more granular
# question — "does the trail set capture *this specific* bucket / Lambda
# surface?" — which means honoring per-resource ARN matching, including
# the wildcard-prefix case (arn:aws:s3::: matches any bucket).
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsCloudtrailDataEventCoverage < AwsResourceBase
  name "aws_cloudtrail_data_event_coverage"
  desc "Cross-trail data-event coverage joining describe_trails × get_event_selectors."
  example "
    describe aws_cloudtrail_data_event_coverage(regions: Array(input('scan_regions'))) do
      it { should log_lambda_data_events }
    end

    describe aws_cloudtrail_data_event_coverage(regions: Array(input('scan_regions')),
                                                 required_s3_bucket_arns: input('required_data_event_bucket_arns')) do
      its('missing_s3_bucket_arns') { should be_empty }
    end
  "

  # The wildcard ARN values that match every bucket / function in the
  # account — both classic-selector data_resources values and equivalent
  # advanced-selector field values.
  S3_WILDCARDS = %w[arn:aws:s3 arn:aws-us-gov:s3 arn:aws:s3:::].freeze
  LAMBDA_WILDCARDS = %w[arn:aws:lambda arn:aws-us-gov:lambda].freeze

  attr_reader :s3_bucket_arns_logged, :lambda_arns_logged

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    @required_s3_bucket_arns = Array(opts.delete(:required_s3_bucket_arns)).map(&:to_s)
    super(opts)
    validate_parameters
    @all_regions = region_override.empty? ? fetch_default_regions : region_override
    fetch_data
  end

  def exists?
    @fetched == true
  end

  def log_lambda_data_events?
    !@lambda_arns_logged.empty?
  end

  def missing_s3_bucket_arns
    return [] if @required_s3_bucket_arns.empty?
    return [] if s3_wildcard_logged?
    @required_s3_bucket_arns.reject { |arn| s3_arn_logged?(arn) }
  end

  def to_s
    "AWS CloudTrail Data Event Coverage"
  end

  private

  def fetch_data
    @fetched = false
    @s3_bucket_arns_logged = []
    @lambda_arns_logged = []
    @s3_wildcard_logged = false

    enumerate_trails.each do |trail|
      ingest_event_selectors(trail)
    end
    @fetched = true
  end

  def enumerate_trails
    trails = []
    seen = {}
    @all_regions.each do |region|
      begin
        client = ::Aws::CloudTrail::Client.new(region: region)
        Array(client.describe_trails.trail_list).each do |t|
          next if seen.key?(t.trail_arn)
          seen[t.trail_arn] = true
          trails << { trail_arn: t.trail_arn, home_region: t.home_region }
        end
      rescue ::Aws::Errors::ServiceError => e
        Inspec::Log.warn("aws_cloudtrail_data_event_coverage: describe_trails in #{region} failed: #{e.message}")
      end
    end
    trails
  end

  def ingest_event_selectors(trail)
    client = ::Aws::CloudTrail::Client.new(region: trail[:home_region])
    resp = client.get_event_selectors(trail_name: trail[:trail_arn])
    Array(resp.event_selectors).each { |es| ingest_classic(es) }
    Array(resp.advanced_event_selectors).each { |aes| ingest_advanced(aes) }
  rescue ::Aws::Errors::ServiceError => e
    Inspec::Log.warn("aws_cloudtrail_data_event_coverage: get_event_selectors(#{trail[:trail_arn]}) failed: #{e.message}")
  end

  def ingest_classic(event_selector)
    Array(event_selector.data_resources).each do |dr|
      values = Array(dr.values).map(&:to_s)
      case dr.type
      when "AWS::S3::Object"
        @s3_wildcard_logged = true if values.any? { |v| s3_wildcard?(v) }
        @s3_bucket_arns_logged.concat(values).uniq!
      when "AWS::Lambda::Function"
        @lambda_arns_logged.concat(values).uniq!
      end
    end
  end

  def ingest_advanced(advanced_event_selector)
    fs_map = Array(advanced_event_selector.field_selectors).each_with_object({}) { |fs, h| h[fs.field] = fs }
    return unless Array(fs_map["eventCategory"]&.equals).include?("Data")

    types = Array(fs_map["resources.type"]&.equals)
    arns_equals = Array(fs_map["resources.ARN"]&.equals).map(&:to_s)
    arn_starts = Array(fs_map["resources.ARN"]&.starts_with).map(&:to_s)

    if types.include?("AWS::S3::Object")
      # Advanced-selector with no resources.ARN restriction = all buckets
      if arns_equals.empty? && arn_starts.empty?
        @s3_wildcard_logged = true
      else
        @s3_wildcard_logged = true if (arns_equals + arn_starts).any? { |v| s3_wildcard?(v) }
        @s3_bucket_arns_logged.concat(arns_equals + arn_starts).uniq!
      end
    end

    if types.include?("AWS::Lambda::Function")
      if arns_equals.empty? && arn_starts.empty?
        @lambda_arns_logged << "arn:aws:lambda"
      else
        @lambda_arns_logged.concat(arns_equals + arn_starts).uniq!
      end
    end
  end

  def s3_wildcard?(value)
    s = value.to_s
    S3_WILDCARDS.any? { |w| s == w || s == "#{w}:::" || s.end_with?(":::") }
  end

  def s3_wildcard_logged?
    @s3_wildcard_logged == true
  end

  def s3_arn_logged?(target_arn)
    return true if s3_wildcard_logged?
    @s3_bucket_arns_logged.any? do |logged|
      l = logged.to_s
      next true if l == target_arn
      # An arn-prefix log entry like "arn:aws:s3:::example-log-archive" covers
      # any object key under that bucket; the bucket itself is captured.
      next true if target_arn.start_with?(l) && (l.end_with?("/") || target_arn[l.length] == "/")
      false
    end
  end

  def fetch_default_regions
    regions = []
    catch_aws_errors do
      regions = @aws.compute_client.describe_regions.regions.map(&:region_name)
    end
    regions
  end
end
