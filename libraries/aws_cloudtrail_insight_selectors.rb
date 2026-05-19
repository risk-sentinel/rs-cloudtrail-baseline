# Insight-event coverage scanner. Walks every visible trail and queries
# `cloudtrail.get_insight_selectors` per-trail; surfaces the set of
# trails with insight selectors configured.
#
# Vendored inspec-aws does not expose insight selectors at all. AWS
# CloudTrail Insight events flag anomalous management-event volume +
# error-rate patterns — strong signal for ransomware / takeover, but not
# enabled by default; this is the surveillance layer §4 doesn't cover.
#
# Depends on `_aws_backend_bootstrap.rb` having loaded first.

class AwsCloudtrailInsightSelectors < AwsResourceBase
  name "aws_cloudtrail_insight_selectors"
  desc "Per-trail insight-event selector enumeration."
  example "
    describe aws_cloudtrail_insight_selectors(regions: Array(input('scan_regions'))) do
      its('trails_with_insight_events') { should_not be_empty }
    end
  "

  attr_reader :rows

  def initialize(opts = {})
    opts = opts.dup
    region_override = Array(opts.delete(:regions))
    super(opts)
    validate_parameters
    @all_regions = region_override.empty? ? fetch_default_regions : region_override
    @rows = fetch_data
  end

  def exists?
    !@rows.empty?
  end

  def trails_with_insight_events
    @rows.reject { |row| row[:insight_types].empty? }
         .map { |row| row[:trail_arn] }
  end

  def trails_with_api_call_rate_insight
    @rows.select { |row| row[:insight_types].include?("ApiCallRateInsight") }
         .map { |row| row[:trail_arn] }
  end

  def trails_with_api_error_rate_insight
    @rows.select { |row| row[:insight_types].include?("ApiErrorRateInsight") }
         .map { |row| row[:trail_arn] }
  end

  def to_s
    "AWS CloudTrail Insight Selectors"
  end

  private

  def fetch_data
    rows = []
    enumerate_trails.each do |trail|
      rows << { trail_arn: trail[:trail_arn], insight_types: fetch_insight_types(trail) }
    end
    rows
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
        Inspec::Log.warn("aws_cloudtrail_insight_selectors: describe_trails in #{region} failed: #{e.message}")
      end
    end
    trails
  end

  def fetch_insight_types(trail)
    client = ::Aws::CloudTrail::Client.new(region: trail[:home_region])
    resp = client.get_insight_selectors(trail_name: trail[:trail_arn])
    Array(resp.insight_selectors).map(&:insight_type).compact
  rescue ::Aws::CloudTrail::Errors::InsightNotEnabledException
    []
  rescue ::Aws::Errors::ServiceError => e
    Inspec::Log.warn("aws_cloudtrail_insight_selectors: get_insight_selectors(#{trail[:trail_arn]}) failed: #{e.message}")
    []
  end

  def fetch_default_regions
    regions = []
    catch_aws_errors do
      regions = @aws.compute_client.describe_regions.regions.map(&:region_name)
    end
    regions
  end
end
