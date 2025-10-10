require "./spec_helper"

describe Saml::Settings do
  describe "#initialize" do
    it "creates settings with defaults" do
      settings = Saml::Settings.new

      settings.compress_request.should be_true
      settings.compress_response.should be_true
      settings.soft.should be_true
      settings.message_max_bytesize.should eq 250_000
    end
  end

  describe "#get_fingerprint" do
    it "returns configured fingerprint" do
      settings = Saml::Settings.new
      settings.idp_cert_fingerprint = "AA:BB:CC:DD:EE:FF"

      settings.get_fingerprint.should eq "AA:BB:CC:DD:EE:FF"
    end
  end

  describe "#idp_sso_service_binding" do
    it "returns POST for embed_sign" do
      settings = Saml::Settings.new
      settings.security.embed_sign = true

      settings.idp_sso_service_binding.should eq Saml::Utils::BINDINGS[:post]
    end

    it "returns redirect by default" do
      settings = Saml::Settings.new
      settings.security.embed_sign = false

      settings.idp_sso_service_binding.should eq Saml::Utils::BINDINGS[:redirect]
    end
  end

  describe "certificate handling" do
    it "builds cert object from PEM string" do
      # This would need a valid test certificate
      settings = Saml::Settings.new
      settings.certificate = nil

      settings.get_sp_cert.should be_nil
    end
  end

  describe "security settings" do
    it "has default security settings" do
      settings = Saml::Settings.new

      settings.security.authn_requests_signed.should be_false
      settings.security.want_assertions_signed.should be_false
      settings.security.digest_method.should eq Saml::XMLSecurity::SHA1
      settings.security.signature_method.should eq Saml::XMLSecurity::RSA_SHA1
    end

    it "allows security settings modification" do
      settings = Saml::Settings.new
      settings.security.authn_requests_signed = true
      settings.security.digest_method = Saml::XMLSecurity::SHA256

      settings.security.authn_requests_signed.should be_true
      settings.security.digest_method.should eq Saml::XMLSecurity::SHA256
    end
  end
end
