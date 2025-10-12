require "./spec_helper"

# Helper to read response files
def read_response(filename)
  path = File.join(__DIR__, "fixtures", "responses", filename)
  content = File.read(path)
  # If filename ends with .base64, it's already base64 encoded
  filename.ends_with?(".base64") ? content.strip : content
end

# Create a test message class that exposes protected methods
class TestSAMLMessage < SAML::SAMLMessage
  def test_decode_raw_saml(saml, settings)
    decode_raw_saml(saml, settings)
  end

  def test_encode_raw_saml(saml, settings)
    encode_raw_saml(saml, settings)
  end

  def test_decode(string)
    decode(string)
  end

  def test_encode(string)
    encode(string)
  end

  def test_deflate(string)
    deflate(string)
  end

  def test_inflate(string)
    inflate(string)
  end

  def test_base64_encoded?(string)
    base64_encoded?(string)
  end
end

# Test data constant
LOGOUT_REQUEST_DOCUMENT = %{<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_some_id" Version="2.0" IssueInstant="2014-07-18T01:13:06Z" Destination="http://idp.example.com/SLO">
  <saml:Issuer>http://sp.example.com</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_some_nameid</saml:NameID>
</samlp:LogoutRequest>}

describe SAML::SAMLMessage do
  describe "#decode" do
    it "decodes base64 encoded string" do
      saml_message = TestSAMLMessage.new
      encoded = "PD94bWwgdmVyc2lvbj0iMS4wIj8+PHNhbWw+dGVzdDwvc2FtbD4="
      decoded = saml_message.test_decode(encoded)
      decoded.should eq("<?xml version=\"1.0\"?><saml>test</saml>")
    end
  end

  describe "#encode" do
    it "encodes string to base64" do
      saml_message = TestSAMLMessage.new
      string = "<?xml version=\"1.0\"?><saml>test</saml>"
      encoded = saml_message.test_encode(string)
      encoded.should eq("PD94bWwgdmVyc2lvbj0iMS4wIj8+PHNhbWw+dGVzdDwvc2FtbD4=")
    end
  end

  describe "#deflate and #inflate" do
    it "deflates and inflates correctly" do
      saml_message = TestSAMLMessage.new
      original = LOGOUT_REQUEST_DOCUMENT
      deflated = saml_message.test_deflate(original)
      inflated = saml_message.test_inflate(deflated)

      # Inflated should match original (allowing for whitespace differences)
      inflated.gsub(/\s+/, " ").should contain("LogoutRequest")
      inflated.should contain("_some_id")
    end

    it "handles SAML responses with real data" do
      saml_message = TestSAMLMessage.new
      original = "<?xml version=\"1.0\"?>\n<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">test</samlp:Response>"
      deflated = saml_message.test_deflate(original)
      inflated = saml_message.test_inflate(deflated)

      inflated.should contain("samlp:Response")
      inflated.should contain("test")
    end
  end

  describe "#base64_encoded?" do
    it "detects base64 encoded strings" do
      saml_message = TestSAMLMessage.new
      saml_message.test_base64_encoded?("PD94bWwgdmVyc2lvbj0iMS4wIj8+").should be_true
      saml_message.test_base64_encoded?("SGVsbG8gV29ybGQ=").should be_true
    end

    it "rejects non-base64 strings" do
      saml_message = TestSAMLMessage.new
      saml_message.test_base64_encoded?("not base64!").should be_false
      saml_message.test_base64_encoded?("<?xml version='1.0'?>").should be_false
    end

    it "handles strings with whitespace" do
      saml_message = TestSAMLMessage.new
      saml_message.test_base64_encoded?("PD94bWw \ndmVyc2lvbj0iMS4wIj8+").should be_true
    end
  end

  describe "#decode_raw_saml" do
    it "decodes base64 encoded SAML" do
      saml_message = TestSAMLMessage.new
      settings = SAML::Settings.new
      encoded = Base64.strict_encode("<saml>test</saml>")
      decoded = saml_message.test_decode_raw_saml(encoded, settings)
      decoded.should eq("<saml>test</saml>")
    end

    it "handles deflated and base64 encoded SAML" do
      saml_message = TestSAMLMessage.new
      settings = SAML::Settings.new
      xml = LOGOUT_REQUEST_DOCUMENT
      deflated = saml_message.test_deflate(xml)
      encoded = Base64.strict_encode(deflated)

      decoded = saml_message.test_decode_raw_saml(encoded, settings)
      decoded.should contain("LogoutRequest")
      decoded.should contain("_some_id")
    end

    it "rejects messages exceeding max bytesize" do
      saml_message = TestSAMLMessage.new
      settings = SAML::Settings.new
      settings.message_max_bytesize = 100
      large_message = "A" * 200

      expect_raises(SAML::ValidationError, /exceeds.*bytes/) do
        saml_message.test_decode_raw_saml(large_message, settings)
      end
    end

    it "rejects deflated messages exceeding max bytesize after inflation" do
      saml_message = TestSAMLMessage.new
      settings = SAML::Settings.new
      # Create a message that's small when deflated but huge when inflated
      large_xml = "<?xml version='1.0'?><data>#{"A" * 300_000}</data>"
      deflated = saml_message.test_deflate(large_xml)
      encoded = Base64.strict_encode(deflated)

      expect_raises(SAML::ValidationError, /exceeds.*bytes/) do
        saml_message.test_decode_raw_saml(encoded, settings)
      end
    end
  end

  describe "#encode_raw_saml" do
    it "encodes with compression" do
      saml_message = TestSAMLMessage.new
      settings = SAML::Settings.new
      settings.compress_request = true
      xml = "<saml>test</saml>"

      encoded = saml_message.test_encode_raw_saml(xml, settings)

      # Should be base64 encoded
      decoded = Base64.decode_string(URI.decode_www_form(encoded))
      # Should be compressed (deflated)
      inflated = saml_message.test_inflate(decoded)
      inflated.should eq(xml)
    end

    it "encodes without compression" do
      saml_message = TestSAMLMessage.new
      settings = SAML::Settings.new
      settings.compress_request = false
      xml = "<saml>test</saml>"

      encoded = saml_message.test_encode_raw_saml(xml, settings)

      # Should be base64 encoded and URL encoded
      decoded = Base64.decode_string(URI.decode_www_form(encoded))
      decoded.should eq(xml)
    end
  end

  describe "with real SAML response files" do
    it "decodes a valid base64 SAML response" do
      saml_message = TestSAMLMessage.new
      settings = SAML::Settings.new
      encoded_response = read_response("valid_response.xml.base64")
      decoded = saml_message.test_decode_raw_saml(encoded_response, settings)

      decoded.should contain("samlp:Response")
      decoded.should contain("Assertion")
    end

    it "handles ADFS response" do
      saml_message = TestSAMLMessage.new
      settings = SAML::Settings.new
      xml = File.read(File.join(__DIR__, "fixtures", "responses", "adfs_response_sha256.xml"))
      encoded = Base64.strict_encode(xml)

      decoded = saml_message.test_decode_raw_saml(encoded, settings)
      decoded.should contain("samlp:Response")
      decoded.should contain("Signature")
    end
  end

  describe "security validations" do
    it "prevents Zlib bomb attacks" do
      saml_message = TestSAMLMessage.new
      settings = SAML::Settings.new
      # Create a small compressed payload that expands to huge size
      bomb_prefix = %{<?xml version='1.0'?><samlp:LogoutRequest><saml:Issuer>}
      bomb_data = bomb_prefix + "A" * 300_000
      bomb_suffix = "</saml:Issuer></samlp:LogoutRequest>"
      bomb_full = bomb_data + bomb_suffix

      deflated = saml_message.test_deflate(bomb_full)
      bomb = Base64.strict_encode(deflated)

      expect_raises(SAML::ValidationError, /exceeds.*bytes/) do
        saml_message.test_decode_raw_saml(bomb, settings)
      end
    end

    it "validates message size before attempting base64 decode" do
      saml_message = TestSAMLMessage.new
      settings = SAML::Settings.new
      # Message larger than max size
      large_message = "A" * (settings.message_max_bytesize + 100)

      expect_raises(SAML::ValidationError, /exceeds.*bytes/) do
        saml_message.test_decode_raw_saml(large_message, settings)
      end
    end
  end
end
