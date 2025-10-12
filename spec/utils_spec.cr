require "./spec_helper"

describe SAML::Utils do
  describe ".uuid" do
    it "generates a UUID with underscore prefix" do
      uuid = SAML::Utils.uuid
      uuid.should start_with("_")
      uuid.size.should eq 37 # _ + 36 char UUID
    end

    it "generates unique UUIDs" do
      uuid1 = SAML::Utils.uuid
      uuid2 = SAML::Utils.uuid
      uuid1.should_not eq uuid2
    end
  end

  describe ".format_cert" do
    it "formats a certificate with proper headers" do
      cert = "MIIDXTCCAkWgAwIBAgIJALmVVuDWu4NYMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV"
      formatted = SAML::Utils.format_cert(cert)

      formatted.should start_with("-----BEGIN CERTIFICATE-----\n")
      formatted.should end_with("\n-----END CERTIFICATE-----")
    end

    it "preserves already formatted certificates" do
      cert = "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJALmVVuDWu4NYMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\n-----END CERTIFICATE-----"
      formatted = SAML::Utils.format_cert(cert)
      formatted.should eq cert
    end
  end

  describe ".format_private_key" do
    it "formats a private key with proper headers" do
      key = "MIIEpQIBAAKCAQEAtxKBw9b54KOBXMfW86rJr1j9lNMTCXGUMq"
      formatted = SAML::Utils.format_private_key(key)

      formatted.should start_with("-----BEGIN PRIVATE KEY-----\n")
      formatted.should end_with("\n-----END PRIVATE KEY-----")
    end

    it "detects RSA private keys" do
      key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAtxKBw9b54KOBXMfW86rJr1j9lNMTCXGUMq\n-----END RSA PRIVATE KEY-----"
      formatted = SAML::Utils.format_private_key(key)
      formatted.should contain("RSA PRIVATE KEY")
    end
  end

  describe ".parse_duration" do
    it "parses ISO 8601 duration" do
      Timecop.freeze(Time.utc(2024, 1, 1, 12, 0, 0)) do
        result = SAML::Utils.parse_duration("PT1H")
        result.should eq Time.utc(2024, 1, 1, 13, 0, 0)
      end
    end

    it "handles negative durations" do
      Timecop.freeze(Time.utc(2024, 1, 1, 12, 0, 0)) do
        result = SAML::Utils.parse_duration("-PT1H")
        result.should eq Time.utc(2024, 1, 1, 11, 0, 0)
      end
    end

    it "handles complex durations" do
      Timecop.freeze(Time.utc(2024, 1, 1, 12, 0, 0)) do
        result = SAML::Utils.parse_duration("P1Y2M3DT4H5M6S")
        result.should eq Time.utc(2025, 3, 4, 16, 5, 6)
      end
    end
  end

  describe ".uri_match?" do
    it "matches identical URIs" do
      url1 = "https://example.com/path"
      url2 = "https://example.com/path"
      SAML::Utils.uri_match?(url1, url2).should be_true
    end

    it "matches URIs case-insensitively for scheme and host" do
      url1 = "HTTPS://EXAMPLE.COM/path"
      url2 = "https://example.com/path"
      SAML::Utils.uri_match?(url1, url2).should be_true
    end

    it "does not match different paths" do
      url1 = "https://example.com/path1"
      url2 = "https://example.com/path2"
      SAML::Utils.uri_match?(url1, url2).should be_false
    end

    it "handles query strings" do
      url1 = "https://example.com/path?foo=bar"
      url2 = "https://example.com/path?foo=bar"
      SAML::Utils.uri_match?(url1, url2).should be_true
    end
  end
end
