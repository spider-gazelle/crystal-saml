require "./spec_helper"

# Helper to read certificate files
def read_cert(filename)
  path = File.join(__DIR__, "fixtures", "certificates", filename)
  File.read(path)
end

# Helper class to access protected inflate method
class TestAuthRequest < SAML::AuthRequest
  def test_inflate(deflated : String) : String
    inflate(deflated)
  end
end

describe "SAML AuthnRequest" do
  describe "Authrequest" do
    it "creates the deflated SAMLRequest URL parameter" do
      settings = SAML::Settings.new
      settings.idp_sso_service_url = "http://example.com"

      request = TestAuthRequest.new
      auth_url = request.create(settings)
      auth_url.should match(/^http:\/\/example\.com\?SAMLRequest=/)

      payload = URI.decode_www_form(auth_url.split("=").last)
      decoded = Base64.decode_string(payload)
      inflated = request.test_inflate(decoded)

      inflated.should contain("<samlp:AuthnRequest")
    end

    it "creates the deflated SAMLRequest URL parameter including the Destination" do
      settings = SAML::Settings.new
      settings.idp_sso_service_url = "http://example.com"

      request = TestAuthRequest.new
      auth_url = request.create(settings)
      payload = URI.decode_www_form(auth_url.split("=").last)
      decoded = Base64.decode_string(payload)
      inflated = request.test_inflate(decoded)

      inflated.should contain("Destination=\"http://example.com\"")
    end

    it "creates the SAMLRequest URL parameter without deflating" do
      settings = SAML::Settings.new
      settings.idp_sso_service_url = "http://example.com"
      settings.compress_request = false

      auth_url = SAML::AuthRequest.new.create(settings)
      auth_url.should match(/^http:\/\/example\.com\?SAMLRequest=/)

      payload = URI.decode_www_form(auth_url.split("=").last)
      decoded = String.new(Base64.decode(payload))

      decoded.should contain("<samlp:AuthnRequest")
    end

    it "creates the SAMLRequest URL parameter with IsPassive" do
      settings = SAML::Settings.new
      settings.idp_sso_service_url = "http://example.com"
      settings.passive = true

      request = TestAuthRequest.new
      auth_url = request.create(settings)
      auth_url.should match(/^http:\/\/example\.com\?SAMLRequest=/)

      payload = URI.decode_www_form(auth_url.split("=").last)
      decoded = Base64.decode_string(payload)
      inflated = request.test_inflate(decoded)

      inflated.should contain("IsPassive=\"true\"")
    end

    it "creates the SAMLRequest URL parameter with ProtocolBinding" do
      settings = SAML::Settings.new
      settings.idp_sso_service_url = "http://example.com"
      settings.protocol_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

      request = TestAuthRequest.new
      auth_url = request.create(settings)
      auth_url.should match(/^http:\/\/example\.com\?SAMLRequest=/)

      payload = URI.decode_www_form(auth_url.split("=").last)
      decoded = Base64.decode_string(payload)
      inflated = request.test_inflate(decoded)

      inflated.should contain("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"")
    end

    it "creates the SAMLRequest URL parameter with AttributeConsumingServiceIndex" do
      settings = SAML::Settings.new
      settings.idp_sso_service_url = "http://example.com"
      settings.attributes_index = 30

      request = TestAuthRequest.new
      auth_url = request.create(settings)
      auth_url.should match(/^http:\/\/example\.com\?SAMLRequest=/)

      payload = URI.decode_www_form(auth_url.split("=").last)
      decoded = Base64.decode_string(payload)
      inflated = request.test_inflate(decoded)

      inflated.should contain("AttributeConsumingServiceIndex=\"30\"")
    end

    it "creates the SAMLRequest URL parameter with ForceAuthn" do
      settings = SAML::Settings.new
      settings.idp_sso_service_url = "http://example.com"
      settings.force_authn = true

      request = TestAuthRequest.new
      auth_url = request.create(settings)
      auth_url.should match(/^http:\/\/example\.com\?SAMLRequest=/)

      payload = URI.decode_www_form(auth_url.split("=").last)
      decoded = Base64.decode_string(payload)
      inflated = request.test_inflate(decoded)

      inflated.should contain("ForceAuthn=\"true\"")
    end

    it "creates the SAMLRequest URL parameter with NameID Format" do
      settings = SAML::Settings.new
      settings.idp_sso_service_url = "http://example.com"
      settings.name_identifier_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

      request = TestAuthRequest.new
      auth_url = request.create(settings)
      auth_url.should match(/^http:\/\/example\.com\?SAMLRequest=/)

      payload = URI.decode_www_form(auth_url.split("=").last)
      decoded = Base64.decode_string(payload)
      inflated = request.test_inflate(decoded)

      inflated.should contain("AllowCreate=\"true\"")
      inflated.should contain("Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\"")
    end

    it "accepts extra parameters" do
      settings = SAML::Settings.new
      settings.idp_sso_service_url = "http://example.com"

      auth_url = SAML::AuthRequest.new.create(settings, {"hello" => "there"})
      auth_url.should match(/&hello=there$/)
    end

    it "handles RelayState cases" do
      settings = SAML::Settings.new
      settings.idp_sso_service_url = "http://example.com"

      # With RelayState
      auth_url = SAML::AuthRequest.new.create(settings, {"RelayState" => "http://example.com"})
      auth_url.should contain("&RelayState=http%3A%2F%2Fexample.com")

      # Without RelayState
      auth_url = SAML::AuthRequest.new.create(settings, {} of String => String)
      auth_url.should_not contain("RelayState")
    end

    it "creates request with ID prefixed with default '_'" do
      request = SAML::AuthRequest.new
      request.uuid.should match(/^_/)
    end

    describe "when the target url doesn't contain a query string" do
      it "creates the SAMLRequest parameter correctly" do
        settings = SAML::Settings.new
        settings.idp_sso_service_url = "http://example.com"

        auth_url = SAML::AuthRequest.new.create(settings)
        auth_url.should match(/^http:\/\/example.com\?SAMLRequest/)
      end
    end

    describe "when the target url contains a query string" do
      it "creates the SAMLRequest parameter correctly" do
        settings = SAML::Settings.new
        settings.idp_sso_service_url = "http://example.com?field=value"

        auth_url = SAML::AuthRequest.new.create(settings)
        auth_url.should match(/^http:\/\/example.com\?field=value&SAMLRequest/)
      end
    end

    it "creates the saml:AuthnContextClassRef element correctly" do
      settings = SAML::Settings.new
      settings.idp_sso_service_url = "http://example.com"
      settings.authn_context = "secure/name/password/uri"

      auth_doc = SAML::AuthRequest.new.create_authentication_xml_doc(settings)
      auth_doc.to_s.should match(/<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/)
    end

    it "creates multiple saml:AuthnContextClassRef elements correctly" do
      settings = SAML::Settings.new
      settings.idp_sso_service_url = "http://example.com"
      settings.authn_context = ["secure/name/password/uri", "secure/email/password/uri"]

      auth_doc = SAML::AuthRequest.new.create_authentication_xml_doc(settings)
      auth_doc.to_s.should match(/<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/)
      auth_doc.to_s.should match(/<saml:AuthnContextClassRef>secure\/email\/password\/uri<\/saml:AuthnContextClassRef>/)
    end

    it "creates the saml:AuthnContextClassRef with comparison exact" do
      settings = SAML::Settings.new
      settings.idp_sso_service_url = "http://example.com"
      settings.authn_context = "secure/name/password/uri"

      auth_doc = SAML::AuthRequest.new.create_authentication_xml_doc(settings)
      auth_doc.to_s.should contain("Comparison=\"exact\"")
      auth_doc.to_s.should match(/<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/)
    end

    it "creates the saml:AuthnContextClassRef with comparison minimum" do
      settings = SAML::Settings.new
      settings.idp_sso_service_url = "http://example.com"
      settings.authn_context = "secure/name/password/uri"
      settings.authn_context_comparison = "minimum"

      auth_doc = SAML::AuthRequest.new.create_authentication_xml_doc(settings)
      auth_doc.to_s.should contain("Comparison=\"minimum\"")
      auth_doc.to_s.should match(/<saml:AuthnContextClassRef>secure\/name\/password\/uri<\/saml:AuthnContextClassRef>/)
    end

    it "creates the saml:AuthnContextDeclRef element correctly" do
      settings = SAML::Settings.new
      settings.idp_sso_service_url = "http://example.com"
      settings.authn_context_decl_ref = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

      auth_doc = SAML::AuthRequest.new.create_authentication_xml_doc(settings)
      auth_doc.to_s.should match(/<saml:AuthnContextDeclRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport<\/saml:AuthnContextDeclRef>/)
    end

    it "creates multiple saml:AuthnContextDeclRef elements correctly" do
      settings = SAML::Settings.new
      settings.idp_sso_service_url = "http://example.com"
      settings.authn_context_decl_ref = ["name/password/uri", "example/decl/ref"]

      auth_doc = SAML::AuthRequest.new.create_authentication_xml_doc(settings)
      auth_doc.to_s.should match(/<saml:AuthnContextDeclRef>name\/password\/uri<\/saml:AuthnContextDeclRef>/)
      auth_doc.to_s.should match(/<saml:AuthnContextDeclRef>example\/decl\/ref<\/saml:AuthnContextDeclRef>/)
    end

    describe "#create_params signing with HTTP-POST binding" do
      it "creates a signed request" do
        settings = SAML::Settings.new
        settings.compress_request = false
        settings.idp_sso_service_url = "http://example.com?field=value"
        settings.security.embed_sign = true # POST binding
        settings.security.authn_requests_signed = true
        settings.certificate = read_cert("ruby-saml.crt")
        settings.private_key = read_cert("ruby-saml.key")

        params = SAML::AuthRequest.new.create_params(settings)
        request_xml = Base64.decode_string(params["SAMLRequest"])

        request_xml.should match(/<ds:SignatureValue>([a-zA-Z0-9\/+=]+)<\/ds:SignatureValue>/)
        request_xml.should match(/<ds:SignatureMethod Algorithm="http:\/\/www.w3.org\/2000\/09\/xmldsig#rsa-sha1"/)
      end

      it "creates a signed request with SHA256 digest and signature methods" do
        settings = SAML::Settings.new
        settings.compress_request = false
        settings.idp_sso_service_url = "http://example.com?field=value"
        settings.security.embed_sign = true # POST binding
        settings.security.authn_requests_signed = true
        settings.security.signature_method = SAML::XMLSecurity::RSA_SHA256
        settings.security.digest_method = SAML::XMLSecurity::SHA512
        settings.certificate = read_cert("ruby-saml.crt")
        settings.private_key = read_cert("ruby-saml.key")

        params = SAML::AuthRequest.new.create_params(settings)
        request_xml = Base64.decode_string(params["SAMLRequest"])

        request_xml.should match(/<ds:SignatureValue>([a-zA-Z0-9\/+=]+)<\/ds:SignatureValue>/)
        request_xml.should match(/<ds:SignatureMethod Algorithm="http:\/\/www.w3.org\/2001\/04\/xmldsig-more#rsa-sha256"/)
        request_xml.should match(/<ds:DigestMethod Algorithm="http:\/\/www.w3.org\/2001\/04\/xmlenc#sha512"/)
      end
    end

    describe "#create_params signing with HTTP-Redirect binding" do
      it "creates a signature parameter with RSA_SHA1 and validates it" do
        settings = SAML::Settings.new
        settings.compress_request = false
        settings.idp_sso_service_url = "http://example.com?field=value"
        settings.security.embed_sign = false # Redirect binding
        settings.assertion_consumer_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"
        settings.security.authn_requests_signed = true
        settings.security.signature_method = SAML::XMLSecurity::RSA_SHA1
        settings.certificate = read_cert("ruby-saml.crt")
        settings.private_key = read_cert("ruby-saml.key")

        params = SAML::AuthRequest.new.create_params(settings, {"RelayState" => "http://example.com"})

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
        settings.idp_sso_service_url = "http://example.com?field=value"
        settings.security.embed_sign = false # Redirect binding
        settings.assertion_consumer_service_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"
        settings.security.authn_requests_signed = true
        settings.security.signature_method = SAML::XMLSecurity::RSA_SHA256
        settings.certificate = read_cert("ruby-saml.crt")
        settings.private_key = read_cert("ruby-saml.key")

        params = SAML::AuthRequest.new.create_params(settings, {"RelayState" => "http://example.com"})

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
        authnrequest = SAML::AuthRequest.new
        request_id = authnrequest.request_id
        request_id.should eq(authnrequest.uuid)

        authnrequest.uuid = "new_uuid"
        authnrequest.request_id.should eq(authnrequest.uuid)
        authnrequest.request_id.should eq("new_uuid")
      end
    end
  end
end
