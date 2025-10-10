require "./spec_helper"

describe Saml::AuthRequest do
  describe "#initialize" do
    it "generates a UUID" do
      request = Saml::AuthRequest.new
      request.uuid.should start_with("_")
      request.uuid.size.should eq 37
    end
  end

  describe "#request_id" do
    it "returns the UUID" do
      request = Saml::AuthRequest.new
      request.request_id.should eq request.uuid
    end
  end

  describe "#create" do
    it "creates an AuthNRequest URL" do
      settings = Saml::Settings.new
      settings.idp_sso_service_url = "https://idp.example.com/sso"
      settings.sp_entity_id = "https://sp.example.com"

      request = Saml::AuthRequest.new
      url = request.create(settings)

      url.should start_with("https://idp.example.com/sso?SAMLRequest=")
    end

    it "includes relay state if provided" do
      settings = Saml::Settings.new
      settings.idp_sso_service_url = "https://idp.example.com/sso"
      settings.sp_entity_id = "https://sp.example.com"

      request = Saml::AuthRequest.new
      url = request.create(settings, {"RelayState" => "target_page"})

      url.should contain("RelayState=target_page")
    end
  end

  describe "#create_authentication_xml_doc" do
    it "creates valid SAML XML" do
      settings = Saml::Settings.new
      settings.idp_sso_service_url = "https://idp.example.com/sso"
      settings.sp_entity_id = "https://sp.example.com"
      settings.assertion_consumer_service_url = "https://sp.example.com/acs"
      settings.name_identifier_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

      request = Saml::AuthRequest.new
      doc = request.create_authentication_xml_doc(settings)

      xml = doc.to_xml
      xml.should contain("samlp:AuthnRequest")
      xml.should contain(request.uuid)
      xml.should contain("https://sp.example.com")
    end

    it "includes NameIDPolicy" do
      settings = Saml::Settings.new
      settings.idp_sso_service_url = "https://idp.example.com/sso"
      settings.name_identifier_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

      request = Saml::AuthRequest.new
      doc = request.create_authentication_xml_doc(settings)

      xml = doc.to_xml
      xml.should contain("samlp:NameIDPolicy")
      xml.should contain("emailAddress")
    end

    it "includes ForceAuthn when set" do
      settings = Saml::Settings.new
      settings.idp_sso_service_url = "https://idp.example.com/sso"
      settings.force_authn = true

      request = Saml::AuthRequest.new
      doc = request.create_authentication_xml_doc(settings)

      xml = doc.to_xml
      xml.should contain("ForceAuthn")
    end

    it "includes IsPassive when set" do
      settings = Saml::Settings.new
      settings.idp_sso_service_url = "https://idp.example.com/sso"
      settings.passive = true

      request = Saml::AuthRequest.new
      doc = request.create_authentication_xml_doc(settings)

      xml = doc.to_xml
      xml.should contain("IsPassive")
    end

    it "includes RequestedAuthnContext" do
      settings = Saml::Settings.new
      settings.idp_sso_service_url = "https://idp.example.com/sso"
      settings.authn_context = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
      settings.authn_context_comparison = "exact"

      request = Saml::AuthRequest.new
      doc = request.create_authentication_xml_doc(settings)

      xml = doc.to_xml
      xml.should contain("samlp:RequestedAuthnContext")
      xml.should contain("Comparison=\"exact\"")
      xml.should contain("PasswordProtectedTransport")
    end
  end
end
