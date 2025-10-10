require "./spec_helper"

# Helper to read metadata files
def read_metadata(filename)
  path = File.join(__DIR__, "fixtures", "metadata", filename)
  File.read(path)
end

describe "SAML Metadata Parsing" do
  describe "IdP metadata descriptor parsing" do
    it "parses entity ID from metadata" do
      xml = read_metadata("idp_descriptor.xml")
      doc = XML.parse(xml)

      entity_desc = doc.xpath_node("//md:EntityDescriptor", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})
      entity_desc.should_not be_nil

      if entity_desc
        entity_id = entity_desc["entityID"]?
        entity_id.should eq("https://hello.example.com/access/saml/idp.xml")
      end
    end

    it "extracts SSO service URL and binding" do
      xml = read_metadata("idp_descriptor.xml")
      doc = XML.parse(xml)

      sso_service = doc.xpath_node("//md:SingleSignOnService", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})
      sso_service.should_not be_nil

      if sso_service
        location = sso_service["Location"]?
        binding = sso_service["Binding"]?

        location.should eq("https://hello.example.com/access/saml/login")
        binding.should eq("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
      end
    end

    it "extracts SLO service URL and binding" do
      xml = read_metadata("idp_descriptor.xml")
      doc = XML.parse(xml)

      slo_service = doc.xpath_node("//md:SingleLogoutService", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})
      slo_service.should_not be_nil

      if slo_service
        location = slo_service["Location"]?
        binding = slo_service["Binding"]?

        location.should eq("https://hello.example.com/access/saml/logout")
        binding.should eq("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
      end
    end

    it "extracts NameID format" do
      xml = read_metadata("idp_descriptor.xml")
      doc = XML.parse(xml)

      name_id_format = doc.xpath_node("//md:NameIDFormat", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})
      name_id_format.should_not be_nil

      if name_id_format
        format = name_id_format.text.strip
        format.should eq("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
      end
    end

    it "extracts X509 certificate from KeyDescriptor" do
      xml = read_metadata("idp_descriptor.xml")
      doc = XML.parse(xml)

      cert_node = doc.xpath_node("//md:KeyDescriptor[@use='signing']//ds:X509Certificate",
        {"md" => "urn:oasis:names:tc:SAML:2.0:metadata", "ds" => "http://www.w3.org/2000/09/xmldsig#"})
      cert_node.should_not be_nil

      if cert_node
        cert_text = cert_node.text.gsub(/\s/, "")
        cert_text.should_not be_empty
        # Certificate should be base64
        cert_text.should match(/^[A-Za-z0-9+\/=]+$/)
      end
    end

    it "extracts ValidUntil from EntityDescriptor" do
      xml = read_metadata("idp_descriptor.xml")
      doc = XML.parse(xml)

      entity_desc = doc.xpath_node("//md:EntityDescriptor", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})
      entity_desc.should_not be_nil

      if entity_desc
        valid_until = entity_desc["validUntil"]?
        valid_until.should eq("2014-04-17T18:02:33.910Z")
      end
    end

    it "extracts attribute names from IDPSSODescriptor" do
      xml = read_metadata("idp_descriptor.xml")
      doc = XML.parse(xml)

      attrs = doc.xpath_nodes("//saml:Attribute", {"saml" => "urn:oasis:names:tc:SAML:2.0:assertion"})
      attrs.size.should eq(2)

      names = attrs.map { |attr| attr["Name"]? }.compact
      names.should eq(["AuthToken", "SSOStartPage"])
    end
  end

  describe "IdP metadata with multiple certificates" do
    it "finds multiple signing certificates" do
      xml = read_metadata("idp_metadata_multi_signing_certs.xml")
      doc = XML.parse(xml)

      signing_certs = doc.xpath_nodes("//md:KeyDescriptor[@use='signing']//ds:X509Certificate",
        {"md" => "urn:oasis:names:tc:SAML:2.0:metadata", "ds" => "http://www.w3.org/2000/09/xmldsig#"})

      signing_certs.size.should eq(3)
    end

    it "distinguishes between signing and encryption certificates" do
      xml = read_metadata("idp_metadata_multi_certs.xml")
      doc = XML.parse(xml)

      signing_certs = doc.xpath_nodes("//md:KeyDescriptor[@use='signing']//ds:X509Certificate",
        {"md" => "urn:oasis:names:tc:SAML:2.0:metadata", "ds" => "http://www.w3.org/2000/09/xmldsig#"})

      encryption_certs = doc.xpath_nodes("//md:KeyDescriptor[@use='encryption']//ds:X509Certificate",
        {"md" => "urn:oasis:names:tc:SAML:2.0:metadata", "ds" => "http://www.w3.org/2000/09/xmldsig#"})

      signing_certs.size.should eq(2)
      encryption_certs.size.should eq(1)
    end

    it "handles same certificate for signing and encryption" do
      xml = read_metadata("idp_metadata_same_sign_and_encrypt_cert.xml")
      doc = XML.parse(xml)

      signing_cert = doc.xpath_node("//md:KeyDescriptor[@use='signing']//ds:X509Certificate",
        {"md" => "urn:oasis:names:tc:SAML:2.0:metadata", "ds" => "http://www.w3.org/2000/09/xmldsig#"})

      encryption_cert = doc.xpath_node("//md:KeyDescriptor[@use='encryption']//ds:X509Certificate",
        {"md" => "urn:oasis:names:tc:SAML:2.0:metadata", "ds" => "http://www.w3.org/2000/09/xmldsig#"})

      signing_cert.should_not be_nil
      encryption_cert.should_not be_nil

      if signing_cert && encryption_cert
        # Both should have same certificate text
        signing_text = signing_cert.text.gsub(/\s/, "")
        encryption_text = encryption_cert.text.gsub(/\s/, "")
        signing_text.should eq(encryption_text)
      end
    end

    it "handles different certificates for signing and encryption" do
      xml = read_metadata("idp_metadata_different_sign_and_encrypt_cert.xml")
      doc = XML.parse(xml)

      signing_cert = doc.xpath_node("//md:KeyDescriptor[@use='signing']//ds:X509Certificate",
        {"md" => "urn:oasis:names:tc:SAML:2.0:metadata", "ds" => "http://www.w3.org/2000/09/xmldsig#"})

      encryption_cert = doc.xpath_node("//md:KeyDescriptor[@use='encryption']//ds:X509Certificate",
        {"md" => "urn:oasis:names:tc:SAML:2.0:metadata", "ds" => "http://www.w3.org/2000/09/xmldsig#"})

      signing_cert.should_not be_nil
      encryption_cert.should_not be_nil

      if signing_cert && encryption_cert
        # Should have different certificate text
        signing_text = signing_cert.text.gsub(/\s/, "")
        encryption_text = encryption_cert.text.gsub(/\s/, "")
        signing_text.should_not eq(encryption_text)
      end
    end
  end

  describe "IdP metadata with multiple descriptors" do
    it "finds multiple EntityDescriptors" do
      xml = read_metadata("idp_multiple_descriptors.xml")
      doc = XML.parse(xml)

      # When there are multiple EntityDescriptors, they're usually wrapped in EntitiesDescriptor
      entity_descriptors = doc.xpath_nodes("//md:EntityDescriptor", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})

      entity_descriptors.size.should be > 1
    end

    it "extracts entity IDs from multiple descriptors" do
      xml = read_metadata("idp_multiple_descriptors.xml")
      doc = XML.parse(xml)

      entity_descriptors = doc.xpath_nodes("//md:EntityDescriptor", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})

      entity_ids = entity_descriptors.map { |ed| ed["entityID"]? }.compact
      entity_ids.should contain("https://foo.example.com/access/saml/idp.xml")
      entity_ids.should contain("https://bar.example.com/access/saml/idp.xml")
    end
  end

  describe "IdP metadata with SLO ResponseLocation" do
    it "extracts different SLO response location when present" do
      xml = read_metadata("idp_different_slo_response_location.xml")
      doc = XML.parse(xml)

      slo_service = doc.xpath_node("//md:SingleLogoutService", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})
      slo_service.should_not be_nil

      if slo_service
        location = slo_service["Location"]?
        response_location = slo_service["ResponseLocation"]?

        location.should eq("https://hello.example.com/access/saml/logout")
        response_location.should eq("https://hello.example.com/access/saml/logout/return")
      end
    end

    it "handles missing ResponseLocation attribute" do
      xml = read_metadata("idp_without_slo_response_location.xml")
      doc = XML.parse(xml)

      slo_service = doc.xpath_node("//md:SingleLogoutService", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})
      slo_service.should_not be_nil

      if slo_service
        location = slo_service["Location"]?
        response_location = slo_service["ResponseLocation"]?

        location.should eq("https://hello.example.com/access/saml/logout")
        response_location.should be_nil
      end
    end
  end

  describe "Metadata validation" do
    it "finds IDPSSODescriptor element" do
      xml = read_metadata("idp_descriptor.xml")
      doc = XML.parse(xml)

      idp_sso_descriptor = doc.xpath_node("//md:IDPSSODescriptor", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})
      idp_sso_descriptor.should_not be_nil
    end

    it "validates protocol support enumeration" do
      xml = read_metadata("idp_descriptor.xml")
      doc = XML.parse(xml)

      idp_sso_descriptor = doc.xpath_node("//md:IDPSSODescriptor", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})

      if idp_sso_descriptor
        protocol = idp_sso_descriptor["protocolSupportEnumeration"]?
        protocol.should eq("urn:oasis:names:tc:SAML:2.0:protocol")
      end
    end

    it "handles metadata without IDPSSODescriptor" do
      xml = read_metadata("no_idp_descriptor.xml")
      doc = XML.parse(xml)

      idp_sso_descriptor = doc.xpath_node("//md:IDPSSODescriptor", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})
      idp_sso_descriptor.should be_nil
    end
  end

  describe "Multiple SSO service bindings" do
    it "finds all SSO service endpoints" do
      xml = read_metadata("idp_descriptor_3.xml")
      doc = XML.parse(xml)

      sso_services = doc.xpath_nodes("//md:SingleSignOnService", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})
      sso_services.size.should be > 1
    end

    it "extracts different binding types" do
      xml = read_metadata("idp_descriptor_3.xml")
      doc = XML.parse(xml)

      sso_services = doc.xpath_nodes("//md:SingleSignOnService", {"md" => "urn:oasis:names:tc:SAML:2.0:metadata"})

      bindings = sso_services.map { |service| service["Binding"]? }.compact.uniq
      bindings.size.should be > 1
    end
  end
end
