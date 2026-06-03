# encoding: UTF-8
#
# document_attestation — source-agnostic "does this evidence document exist,
# and is it current?" accessor. Lifts policy / periodic-review controls from
# Skip-with-rationale to Pass-with-evidence based on the existence + freshness
# of an attestation (or leveraged-system evidence) document at a URI.
#
# Schemes:
#   s3://bucket/key   — primary; lazy-loads aws-sdk-s3 and uses the ambient
#                       AWS credential chain (the OIDC creds the exec job
#                       exports). Requires the caller's role to have
#                       s3:GetObject on the key AND kms:Decrypt on the bucket
#                       CMK (HeadObject on an SSE-KMS object needs it).
#   https://host/path — HTTP HEAD; parses the Last-Modified header.
#   file:///path      — local file mtime. Bare paths are aliased to this.
#
# Accessors:
#   exists?            -> Boolean
#   last_modified      -> Time | nil
#   current?(days=nil) -> Boolean   (existence-only when no window given)
#   connection_error   -> String | nil
#   attestation_json   -> Hash | nil  (parsed CMS-pattern JSON, lazy)
#
# A populated connection_error means the document could not be reached
# (missing IAM/KMS grant, network failure, malformed URI). Controls surface it
# as a FAIL rather than a vacuous pass. file:// and https:// need no AWS creds,
# so the resource is reusable by any consumer pointing at any evidence store.
#
# Design notes: docs/dev/Vendored_Resource_Gaps.md (document-as-evidence).

class DocumentAttestation < Inspec.resource(1)
  name "document_attestation"
  supports platform: "aws"
  desc "Existence + freshness of an evidence/attestation document at a URI (s3/https/file)."
  example <<~EXAMPLE
    describe document_attestation('s3://my-bucket/attestations/C-2.1.3.json', max_age_days: 365) do
      it { should exist }
      it { should be_current }
    end
  EXAMPLE

  attr_reader :uri, :scheme, :last_modified, :connection_error

  def initialize(uri = nil, max_age_days: nil, region: nil)
    if uri.is_a?(Hash)
      opts          = uri
      uri           = opts[:uri]
      max_age_days ||= opts[:max_age_days]
      region       ||= opts[:region]
    end
    @uri              = uri.to_s
    @max_age_days     = max_age_days
    @region           = region || ENV["AWS_REGION"] || "us-east-1"
    @exists           = false
    @last_modified    = nil
    @connection_error = nil
    @raw_body         = nil
    @scheme           = nil

    if @uri.empty?
      @connection_error = "no document URI configured"
      return
    end
    fetch
  end

  def exists?
    @exists == true
  end

  # Existence-only when no window is given (any existing doc is "current");
  # otherwise the document must have been modified within the window.
  def current?(max_age_days = nil)
    days = max_age_days || @max_age_days
    return false unless @exists && @last_modified
    return true if days.nil?
    @last_modified > (Time.now - (days.to_i * 86_400))
  end

  def attestation_json
    return @attestation_json if defined?(@attestation_json)
    @attestation_json =
      begin
        require "json"
        body = fetch_body
        body ? JSON.parse(body) : nil
      rescue JSON::ParserError, StandardError
        nil
      end
  end

  def to_s
    "Document Attestation '#{@uri}'"
  end

  private

  def fetch
    case @uri
    when %r{\As3://}     then fetch_s3
    when %r{\Ahttps?://} then fetch_http
    when %r{\Afile://}   then fetch_file(@uri.sub(%r{\Afile://}, ""))
    else                      fetch_file(@uri) # bare-path alias
    end
  end

  def fetch_s3
    @scheme = "s3"
    m = @uri.match(%r{\As3://([^/]+)/(.+)\z})
    return (@connection_error = "malformed s3 URI: #{@uri}") unless m
    @s3_bucket, @s3_key = m[1], m[2]
    begin
      require "aws-sdk-s3"
      resp = s3_client.head_object(bucket: @s3_bucket, key: @s3_key)
      @exists        = true
      @last_modified = resp.last_modified
    rescue Aws::S3::Errors::NotFound, Aws::S3::Errors::NoSuchKey
      @exists = false
    rescue Aws::S3::Errors::Forbidden, Aws::S3::Errors::AccessDenied => e
      @connection_error = "S3 access denied for #{@uri} (#{e.class.name.split('::').last}) — " \
                          "check the role's s3:GetObject + kms:Decrypt on the bucket CMK."
    rescue StandardError => e
      @connection_error = "S3 head_object failed for #{@uri}: #{e.class}: #{e.message}"
    end
  end

  def fetch_http
    @scheme = "https"
    require "net/http"
    require "uri"
    require "time"
    parsed = URI.parse(@uri)
    resp = Net::HTTP.start(parsed.host, parsed.port, use_ssl: parsed.scheme == "https") do |http|
      http.head(parsed.request_uri)
    end
    if resp.is_a?(Net::HTTPSuccess)
      @exists = true
      lm = resp["last-modified"]
      @last_modified = lm ? Time.httpdate(lm) : nil
    elsif resp.is_a?(Net::HTTPNotFound)
      @exists = false
    else
      @connection_error = "HTTP #{resp.code} for #{@uri}"
    end
  rescue StandardError => e
    @connection_error = "HTTP HEAD failed for #{@uri}: #{e.class}: #{e.message}"
  end

  def fetch_file(path)
    @scheme = "file"
    if File.exist?(path) && File.readable?(path)
      @exists        = true
      @last_modified = File.mtime(path)
    else
      @exists = false
    end
  rescue StandardError => e
    @connection_error = "file read failed for #{@uri}: #{e.class}: #{e.message}"
  end

  def fetch_body
    case @scheme
    when "s3"
      return nil unless @exists
      require "aws-sdk-s3"
      s3_client.get_object(bucket: @s3_bucket, key: @s3_key).body.read
    when "https"
      require "net/http"
      require "uri"
      Net::HTTP.get(URI.parse(@uri))
    when "file"
      path = @uri.sub(%r{\Afile://}, "")
      File.read(path) if File.exist?(path)
    end
  rescue StandardError
    nil
  end

  def s3_client
    @s3_client ||= Aws::S3::Client.new(region: @region)
  end
end
