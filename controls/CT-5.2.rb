# encoding: UTF-8

control 'C-CT-5.2' do
  title "Ensure CloudTrail bucket policy denies non-TLS PUT"
  desc  "
    The trail bucket's policy should explicitly deny any `PutObject` call (or broader `s3:*` / `*`) when `aws:SecureTransport == false`. This is the canonical S3 'TLS only' pattern; it forces every CloudTrail log delivery (and any operator interaction) to use HTTPS.

    Statement match criteria:
    - `Effect == 'Deny'`
    - `Action` includes `s3:PutObject` (or `s3:Put*`, `s3:*`, `*`)
    - `Condition.Bool` (or `BoolIfExists`) has `aws:SecureTransport == 'false'`
  "
  desc  'rationale', "
    Without this deny, an in-region MITM (rare, but in scope for high-assurance environments) could intercept a plaintext log-delivery request. More commonly, this control catches a mis-scoped allow rule that didn't carry the TLS condition forward — a subtle policy regression invisible from the bucket's permission summary.
  "
  desc  'check', "
    ```
    aws s3api get-bucket-policy --bucket <name>
    ```

    Confirm a Deny statement matching the criteria above.
  "
  desc  'fix', "
    Add the canonical TLS-deny statement:

    ```
    {
      \"Sid\": \"DenyInsecureTransport\",
      \"Effect\": \"Deny\",
      \"Principal\": \"*\",
      \"Action\": \"s3:*\",
      \"Resource\": [
        \"arn:aws:s3:::<bucket>\",
        \"arn:aws:s3:::<bucket>/*\"
      ],
      \"Condition\": {
        \"Bool\": { \"aws:SecureTransport\": \"false\" }
      }
    }
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-8', 'SC-13']
  tag cis_number:            'CT-5.2'
  tag cis_rid:               'CT-5.2'
  tag cis_benchmark:         'the consumer CloudTrail Baseline'
  tag cis_rule_id:           'the consumer-CT-5.2'
  tag cis_version:           '0.1.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag applicable_partitions: ['aws', 'aws-us-gov']
  tag implementation_status: 'implemented'
  tag attestation_category:  'operational'

  applicable_partition = ['aws', 'aws-us-gov'].include?(input('aws_partition'))
  applicable           = applicable_partition

  impact 0.5
  impact 0.0 unless applicable

  only_if("Control out of scope (partition=#{input('aws_partition')})") do
    applicable
  end

  trail_status = aws_cloudtrail_trail_status(regions: Array(input('scan_regions')),
                                              delivery_recency_hours: input('trail_delivery_recency_hours'))
  buckets = trail_status.trail_buckets

  if buckets.empty?
    describe 'Trail-bucket TLS-deny policy (no trails configured)' do
      skip 'no visible trails — nothing to inspect.'
    end
  else
    # `should be_deny_non_tls_put` (with `be_` prefix) is the idiomatic
    # predicate-matcher form — RSpec resolves it to
    # `subject.deny_non_tls_put?`. Bare `should deny_non_tls_put`
    # without the prefix is interpreted as a custom matcher name and
    # fails at exec time with "undefined local variable or method
    # 'deny_non_tls_put'". See feedback_inspec_predicate_matchers.md.
    buckets.each do |bucket|
      describe aws_s3_bucket_features(bucket_name: bucket) do
        it { should be_deny_non_tls_put }
      end
    end
  end
end
