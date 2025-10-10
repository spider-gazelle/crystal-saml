require "./spec_helper"

# Helper to read certificate files
def read_cert(filename)
  path = File.join(__DIR__, "fixtures", "certificates", filename)
  File.read(path)
end

describe "SAML LogoutResponse" do
  describe "LogoutResponse" do
    it "creates a LogoutResponse" do
      settings = Saml::Settings.new
      settings.idp_slo_response_service_url = "http://example.com/slo"
      settings.sp_entity_id = "https://sp.example.com"

      logout_response = Saml::LogoutResponse.create(settings, "_request_id_123")
      logout_response.should contain("SAMLResponse=")
    end

    it "includes InResponseTo when request_id is provided" do
      settings = Saml::Settings.new
      settings.compress_response = false # Don't compress for easier testing
      settings.idp_slo_response_service_url = "http://example.com/slo"
      settings.sp_entity_id = "https://sp.example.com"

      logout_response = Saml::LogoutResponse.create(settings, "_request_id_123")

      # Decode and check the response
      params = logout_response.split("SAMLResponse=")[1].split("&")[0]
      decoded = String.new(Base64.decode(URI.decode_www_form(params)))

      decoded.should contain("InResponseTo=\"_request_id_123\"")
    end

    it "does not include InResponseTo when request_id is nil" do
      settings = Saml::Settings.new
      settings.compress_response = false
      settings.idp_slo_response_service_url = "http://example.com/slo"
      settings.sp_entity_id = "https://sp.example.com"

      logout_response = Saml::LogoutResponse.create(settings, nil)

      # Decode and check the response
      params = logout_response.split("SAMLResponse=")[1].split("&")[0]
      decoded = String.new(Base64.decode(URI.decode_www_form(params)))

      decoded.should_not contain("InResponseTo")
    end

    it "includes status message when provided" do
      settings = Saml::Settings.new
      settings.compress_response = false
      settings.idp_slo_response_service_url = "http://example.com/slo"
      settings.sp_entity_id = "https://sp.example.com"

      logout_response = Saml::LogoutResponse.create(settings, "_request_id_123", "Logout successful")

      # Decode and check the response
      params = logout_response.split("SAMLResponse=")[1].split("&")[0]
      decoded = String.new(Base64.decode(URI.decode_www_form(params)))

      decoded.should contain("<samlp:StatusMessage>Logout successful</samlp:StatusMessage>")
    end

    it "includes issuer when sp_entity_id is set" do
      settings = Saml::Settings.new
      settings.compress_response = false
      settings.idp_slo_response_service_url = "http://example.com/slo"
      settings.sp_entity_id = "https://sp.example.com"

      logout_response = Saml::LogoutResponse.create(settings, "_request_id_123")

      # Decode and check the response
      params = logout_response.split("SAMLResponse=")[1].split("&")[0]
      decoded = String.new(Base64.decode(URI.decode_www_form(params)))

      decoded.should contain("<saml:Issuer>https://sp.example.com</saml:Issuer>")
    end

    it "includes destination" do
      settings = Saml::Settings.new
      settings.compress_response = false
      settings.idp_slo_response_service_url = "http://example.com/slo/response"
      settings.sp_entity_id = "https://sp.example.com"

      logout_response = Saml::LogoutResponse.create(settings, "_request_id_123")

      # Decode and check the response
      params = logout_response.split("SAMLResponse=")[1].split("&")[0]
      decoded = String.new(Base64.decode(URI.decode_www_form(params)))

      decoded.should contain("Destination=\"http://example.com/slo/response\"")
    end

    it "handles RelayState parameter" do
      settings = Saml::Settings.new
      settings.idp_slo_response_service_url = "http://example.com/slo"
      settings.sp_entity_id = "https://sp.example.com"

      logout_response = Saml::LogoutResponse.create(settings, "_request_id_123", nil, {"RelayState" => "http://example.com/return"})
      logout_response.should contain("RelayState=http%3A%2F%2Fexample.com%2Freturn")
    end

    it "creates response with ID prefixed with default '_'" do
      settings = Saml::Settings.new
      settings.compress_response = false
      settings.idp_slo_response_service_url = "http://example.com/slo"
      settings.sp_entity_id = "https://sp.example.com"

      logout_response = Saml::LogoutResponse.create(settings, "_request_id_123")

      # Decode and check the response
      params = logout_response.split("SAMLResponse=")[1].split("&")[0]
      decoded = String.new(Base64.decode(URI.decode_www_form(params)))

      decoded.should match(/ID="_[a-f0-9-]+"/)
    end

    it "includes Success status code" do
      settings = Saml::Settings.new
      settings.compress_response = false
      settings.idp_slo_response_service_url = "http://example.com/slo"
      settings.sp_entity_id = "https://sp.example.com"

      logout_response = Saml::LogoutResponse.create(settings, "_request_id_123")

      # Decode and check the response
      params = logout_response.split("SAMLResponse=")[1].split("&")[0]
      decoded = String.new(Base64.decode(URI.decode_www_form(params)))

      decoded.should contain("Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"")
    end

    describe "parsing received LogoutResponse" do
      it "parses a basic logout response" do
        # Create a response XML
        response_xml = <<-XML
        <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                              xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                              ID="_response_id"
                              Version="2.0"
                              IssueInstant="2010-11-18T21:57:37Z"
                              InResponseTo="_request_id">
          <saml:Issuer>https://idp.example.com</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
          </samlp:Status>
        </samlp:LogoutResponse>
        XML

        settings = Saml::Settings.new
        settings.idp_entity_id = "https://idp.example.com"

        encoded_response = Base64.strict_encode(response_xml)
        response = Saml::LogoutResponse.new(encoded_response, settings)

        response.success?.should be_true
        response.status_code.should eq("urn:oasis:names:tc:SAML:2.0:status:Success")
        response.in_response_to.should eq("_request_id")
        response.issuer.should eq("https://idp.example.com")
      end

      it "extracts status message when present" do
        response_xml = <<-XML
        <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                              xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                              ID="_response_id"
                              Version="2.0"
                              IssueInstant="2010-11-18T21:57:37Z">
          <saml:Issuer>https://idp.example.com</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
            <samlp:StatusMessage>Logout completed successfully</samlp:StatusMessage>
          </samlp:Status>
        </samlp:LogoutResponse>
        XML

        settings = Saml::Settings.new
        encoded_response = Base64.strict_encode(response_xml)
        response = Saml::LogoutResponse.new(encoded_response, settings)

        response.status_message.should eq("Logout completed successfully")
      end

      it "returns false when status is not Success" do
        response_xml = <<-XML
        <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                              xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                              ID="_response_id"
                              Version="2.0"
                              IssueInstant="2010-11-18T21:57:37Z">
          <saml:Issuer>https://idp.example.com</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/>
          </samlp:Status>
        </samlp:LogoutResponse>
        XML

        settings = Saml::Settings.new
        settings.idp_entity_id = "https://idp.example.com"
        encoded_response = Base64.strict_encode(response_xml)
        response = Saml::LogoutResponse.new(encoded_response, settings)

        response.success?.should be_false
        response.valid?.should be_false
      end

      it "validates issuer matches expected IdP" do
        response_xml = <<-XML
        <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                              xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                              ID="_response_id"
                              Version="2.0"
                              IssueInstant="2010-11-18T21:57:37Z">
          <saml:Issuer>https://wrong-idp.example.com</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
          </samlp:Status>
        </samlp:LogoutResponse>
        XML

        settings = Saml::Settings.new
        settings.idp_entity_id = "https://idp.example.com"
        encoded_response = Base64.strict_encode(response_xml)
        response = Saml::LogoutResponse.new(encoded_response, settings)

        response.valid?.should be_false
        response.errors.any? { |e| e.includes?("Issuer mismatch") }.should be_true
      end

      it "validates response has an ID" do
        response_xml = <<-XML
        <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                              xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                              Version="2.0"
                              IssueInstant="2010-11-18T21:57:37Z">
          <saml:Issuer>https://idp.example.com</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
          </samlp:Status>
        </samlp:LogoutResponse>
        XML

        settings = Saml::Settings.new
        settings.idp_entity_id = "https://idp.example.com"
        encoded_response = Base64.strict_encode(response_xml)
        response = Saml::LogoutResponse.new(encoded_response, settings)

        response.valid?.should be_false
        response.errors.any? { |e| e.includes?("Missing ID attribute") }.should be_true
      end

      it "validates SAML version is 2.0" do
        response_xml = <<-XML
        <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                              xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                              ID="_response_id"
                              Version="1.1"
                              IssueInstant="2010-11-18T21:57:37Z">
          <saml:Issuer>https://idp.example.com</saml:Issuer>
          <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
          </samlp:Status>
        </samlp:LogoutResponse>
        XML

        settings = Saml::Settings.new
        settings.idp_entity_id = "https://idp.example.com"
        encoded_response = Base64.strict_encode(response_xml)
        response = Saml::LogoutResponse.new(encoded_response, settings)

        response.valid?.should be_false
        response.errors.any? { |e| e.includes?("Unsupported SAML version") }.should be_true
      end
    end
  end
end
