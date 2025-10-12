require "./spec_helper"

# Helper to read certificate files
def read_cert(filename)
  path = File.join(__DIR__, "fixtures", "certificates", filename)
  File.read(path)
end

# Helper class to access protected inflate method
class TestLogoutRequest < SAML::LogoutRequest
  def test_inflate(deflated : String) : String
    inflate(deflated)
  end
end

describe "SAML LogoutRequest" do
  describe "LogoutRequest" do
    it "creates the deflated SAMLRequest URL parameter" do
      settings = SAML::Settings.new
      settings.idp_slo_service_url = "http://example.com/slo"
      settings.name_identifier_value = "user@example.com"

      request = TestLogoutRequest.new
      logout_url = request.create(settings)
      logout_url.should match(/^http:\/\/example\.com\/slo\?SAMLRequest=/)

      payload = URI.decode_www_form(logout_url.split("=", 2).last.split("&").first)
      decoded = Base64.decode_string(payload)
      inflated = request.test_inflate(decoded)

      inflated.should contain("<samlp:LogoutRequest")
      inflated.should contain("user@example.com")
    end

    it "creates the deflated SAMLRequest URL parameter including the Destination" do
      settings = SAML::Settings.new
      settings.idp_slo_service_url = "http://example.com/slo"
      settings.name_identifier_value = "user@example.com"

      request = TestLogoutRequest.new
      logout_url = request.create(settings)
      payload = URI.decode_www_form(logout_url.split("=", 2).last.split("&").first)
      decoded = Base64.decode_string(payload)
      inflated = request.test_inflate(decoded)

      inflated.should contain("Destination=\"http://example.com/slo\"")
    end

    it "creates the SAMLRequest URL parameter without deflating" do
      settings = SAML::Settings.new
      settings.idp_slo_service_url = "http://example.com/slo"
      settings.compress_request = false
      settings.name_identifier_value = "user@example.com"

      logout_url = SAML::LogoutRequest.new.create(settings)
      logout_url.should match(/^http:\/\/example\.com\/slo\?SAMLRequest=/)

      payload = URI.decode_www_form(logout_url.split("=", 2).last.split("&").first)
      decoded = String.new(Base64.decode(payload))

      decoded.should contain("<samlp:LogoutRequest")
      decoded.should contain("user@example.com")
    end

    it "includes the NameID in the request" do
      settings = SAML::Settings.new
      settings.idp_slo_service_url = "http://example.com/slo"
      settings.name_identifier_value = "user@example.com"
      settings.name_identifier_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

      request = TestLogoutRequest.new
      logout_url = request.create(settings)
      payload = URI.decode_www_form(logout_url.split("=", 2).last.split("&").first)
      decoded = Base64.decode_string(payload)
      inflated = request.test_inflate(decoded)

      inflated.should contain("user@example.com")
      inflated.should contain("Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\"")
    end

    it "includes the SessionIndex in the request when provided" do
      settings = SAML::Settings.new
      settings.idp_slo_service_url = "http://example.com/slo"
      settings.name_identifier_value = "user@example.com"
      settings.sessionindex = "_session_12345"

      request = TestLogoutRequest.new
      logout_url = request.create(settings)
      payload = URI.decode_www_form(logout_url.split("=", 2).last.split("&").first)
      decoded = Base64.decode_string(payload)
      inflated = request.test_inflate(decoded)

      inflated.should contain("<samlp:SessionIndex>_session_12345</samlp:SessionIndex>")
    end

    it "includes the Issuer in the request when sp_entity_id is set" do
      settings = SAML::Settings.new
      settings.idp_slo_service_url = "http://example.com/slo"
      settings.sp_entity_id = "https://sp.example.com"
      settings.name_identifier_value = "user@example.com"

      request = TestLogoutRequest.new
      logout_url = request.create(settings)
      payload = URI.decode_www_form(logout_url.split("=", 2).last.split("&").first)
      decoded = Base64.decode_string(payload)
      inflated = request.test_inflate(decoded)

      inflated.should contain("<saml:Issuer>https://sp.example.com</saml:Issuer>")
    end

    it "includes NameQualifier when idp_name_qualifier is set" do
      settings = SAML::Settings.new
      settings.idp_slo_service_url = "http://example.com/slo"
      settings.name_identifier_value = "user@example.com"
      settings.idp_name_qualifier = "https://idp.example.com"

      request = TestLogoutRequest.new
      logout_url = request.create(settings)
      payload = URI.decode_www_form(logout_url.split("=", 2).last.split("&").first)
      decoded = Base64.decode_string(payload)
      inflated = request.test_inflate(decoded)

      inflated.should contain("NameQualifier=\"https://idp.example.com\"")
    end

    it "includes SPNameQualifier when sp_name_qualifier is set" do
      settings = SAML::Settings.new
      settings.idp_slo_service_url = "http://example.com/slo"
      settings.name_identifier_value = "user@example.com"
      settings.sp_name_qualifier = "https://sp.example.com"

      request = TestLogoutRequest.new
      logout_url = request.create(settings)
      payload = URI.decode_www_form(logout_url.split("=", 2).last.split("&").first)
      decoded = Base64.decode_string(payload)
      inflated = request.test_inflate(decoded)

      inflated.should contain("SPNameQualifier=\"https://sp.example.com\"")
    end

    it "accepts extra parameters" do
      settings = SAML::Settings.new
      settings.idp_slo_service_url = "http://example.com/slo"
      settings.name_identifier_value = "user@example.com"

      logout_url = SAML::LogoutRequest.new.create(settings, {"hello" => "there"})
      logout_url.should match(/&hello=there$/)
    end

    it "handles RelayState parameter" do
      settings = SAML::Settings.new
      settings.idp_slo_service_url = "http://example.com/slo"
      settings.name_identifier_value = "user@example.com"

      # With RelayState
      logout_url = SAML::LogoutRequest.new.create(settings, {"RelayState" => "http://example.com/return"})
      logout_url.should contain("&RelayState=http%3A%2F%2Fexample.com%2Freturn")

      # Without RelayState
      logout_url = SAML::LogoutRequest.new.create(settings, {} of String => String)
      logout_url.should_not contain("RelayState")
    end

    it "creates request with ID prefixed with default '_'" do
      request = SAML::LogoutRequest.new
      request.uuid.should match(/^_/)
    end

    describe "when the target url doesn't contain a query string" do
      it "creates the SAMLRequest parameter correctly" do
        settings = SAML::Settings.new
        settings.idp_slo_service_url = "http://example.com/slo"
        settings.name_identifier_value = "user@example.com"

        logout_url = SAML::LogoutRequest.new.create(settings)
        logout_url.should match(/^http:\/\/example\.com\/slo\?SAMLRequest/)
      end
    end

    describe "when the target url contains a query string" do
      it "creates the SAMLRequest parameter correctly" do
        settings = SAML::Settings.new
        settings.idp_slo_service_url = "http://example.com/slo?field=value"
        settings.name_identifier_value = "user@example.com"

        logout_url = SAML::LogoutRequest.new.create(settings)
        logout_url.should match(/^http:\/\/example\.com\/slo\?field=value&SAMLRequest/)
      end
    end

    describe "#create_params signing with HTTP-Redirect binding" do
      it "creates a signature parameter with RSA_SHA1 and validates it" do
        settings = SAML::Settings.new
        settings.compress_request = false
        settings.idp_slo_service_url = "http://example.com/slo"
        settings.security.embed_sign = false # Redirect binding
        settings.name_identifier_value = "user@example.com"
        settings.security.logout_requests_signed = true
        settings.security.signature_method = SAML::XMLSecurity::RSA_SHA1
        settings.certificate = read_cert("ruby-saml.crt")
        settings.private_key = read_cert("ruby-saml.key")

        params = SAML::LogoutRequest.new.create_params(settings, {"RelayState" => "http://example.com"})

        params["SAMLRequest"]?.should_not be_nil
        params["RelayState"]?.should_not be_nil
        params["Signature"]?.should_not be_nil
        params["SigAlg"]?.should eq(SAML::XMLSecurity::RSA_SHA1)

        # Verify signature
        cert_text = read_cert("ruby-saml.crt")
        cert = OpenSSL::X509::Certificate.new(cert_text)

        query_string = "SAMLRequest=#{URI.encode_www_form(params["SAMLRequest"])}"
        query_string += "&RelayState=#{URI.encode_www_form(params["RelayState"])}"
        query_string += "&SigAlg=#{URI.encode_www_form(params["SigAlg"])}"

        signature_algorithm = SAML::XMLSecurity.signature_algorithm(params["SigAlg"])
        signature_bytes = Base64.decode(params["Signature"])

        cert.public_key.verify(signature_algorithm, signature_bytes, query_string.to_slice).should be_true
      end

      it "creates a signature parameter with RSA_SHA256 and validates it" do
        settings = SAML::Settings.new
        settings.compress_request = false
        settings.idp_slo_service_url = "http://example.com/slo"
        settings.security.embed_sign = false # Redirect binding
        settings.name_identifier_value = "user@example.com"
        settings.security.logout_requests_signed = true
        settings.security.signature_method = SAML::XMLSecurity::RSA_SHA256
        settings.certificate = read_cert("ruby-saml.crt")
        settings.private_key = read_cert("ruby-saml.key")

        params = SAML::LogoutRequest.new.create_params(settings, {"RelayState" => "http://example.com"})

        params["Signature"]?.should_not be_nil
        params["SigAlg"]?.should eq(SAML::XMLSecurity::RSA_SHA256)

        # Verify signature
        cert_text = read_cert("ruby-saml.crt")
        cert = OpenSSL::X509::Certificate.new(cert_text)

        query_string = "SAMLRequest=#{URI.encode_www_form(params["SAMLRequest"])}"
        query_string += "&RelayState=#{URI.encode_www_form(params["RelayState"])}"
        query_string += "&SigAlg=#{URI.encode_www_form(params["SigAlg"])}"

        signature_algorithm = SAML::XMLSecurity.signature_algorithm(params["SigAlg"])
        signature_bytes = Base64.decode(params["Signature"])

        cert.public_key.verify(signature_algorithm, signature_bytes, query_string.to_slice).should be_true
      end
    end

    describe "#manipulate request_id" do
      it "is able to modify the request id" do
        logoutrequest = SAML::LogoutRequest.new
        request_id = logoutrequest.request_id
        request_id.should eq(logoutrequest.uuid)

        logoutrequest.uuid = "new_uuid"
        logoutrequest.request_id.should eq(logoutrequest.uuid)
        logoutrequest.request_id.should eq("new_uuid")
      end
    end

    describe "generates a transient NameID when no name_identifier_value is provided" do
      it "uses a transient format" do
        settings = SAML::Settings.new
        settings.idp_slo_service_url = "http://example.com/slo"
        # Don't set name_identifier_value

        request = TestLogoutRequest.new
        logout_url = request.create(settings)
        payload = URI.decode_www_form(logout_url.split("=", 2).last.split("&").first)
        decoded = Base64.decode_string(payload)
        inflated = request.test_inflate(decoded)

        inflated.should contain("Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\"")
        inflated.should contain("<saml:NameID")
      end
    end
  end
end
