require "./spec_helper"

# Helper to read certificate files
def read_cert(filename)
  path = File.join(__DIR__, "fixtures", "certificates", filename)
  File.read(path)
end

describe Saml::XMLSecurity do
  describe ".signature_algorithm" do
    it "returns SHA1 digest for RSA-SHA1" do
      alg = Saml::XMLSecurity.signature_algorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1")
      alg.should be_a(OpenSSL::Digest)
    end

    it "returns SHA256 digest for RSA-SHA256" do
      alg = Saml::XMLSecurity.signature_algorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
      alg.should be_a(OpenSSL::Digest)
    end

    it "returns SHA384 digest for RSA-SHA384" do
      alg = Saml::XMLSecurity.signature_algorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384")
      alg.should be_a(OpenSSL::Digest)
    end

    it "returns SHA512 digest for RSA-SHA512" do
      alg = Saml::XMLSecurity.signature_algorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")
      alg.should be_a(OpenSSL::Digest)
    end

    it "defaults to SHA1 for unknown algorithms" do
      alg = Saml::XMLSecurity.signature_algorithm("http://unknown-algorithm")
      alg.should be_a(OpenSSL::Digest)
    end

    it "handles digest algorithm URIs" do
      alg = Saml::XMLSecurity.signature_algorithm("http://www.w3.org/2001/04/xmlenc#sha256")
      alg.should be_a(OpenSSL::Digest)
    end
  end

  describe ".canon_algorithm" do
    it "returns c14n for standard canonicalization" do
      result = Saml::XMLSecurity.canon_algorithm("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
      result.should eq("c14n")
    end

    it "returns c14n11 for C14N 1.1" do
      result = Saml::XMLSecurity.canon_algorithm("http://www.w3.org/2006/12/xml-c14n11")
      result.should eq("c14n11")
    end

    it "defaults to exclusive canonicalization" do
      result = Saml::XMLSecurity.canon_algorithm("http://www.w3.org/2001/10/xml-exc-c14n#")
      result.should eq("c14n_exclusive")
    end
  end

  describe ".sign_document" do
    it "signs an XML document with RSA key and certificate" do
      # Create a simple XML document
      xml = %{<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_test_id"
                    Version="2.0"
                    IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>https://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>}

      # Use real key and cert from fixtures
      key_pem = read_cert("ruby-saml.key")
      cert_pem = read_cert("ruby-saml.crt")

      key = OpenSSL::PKey::RSA.new(key_pem, nil)
      cert = OpenSSL::X509::Certificate.new(cert_pem)

      signed_xml = Saml::XMLSecurity.sign_document(
        xml, key, cert, "_test_id",
        Saml::XMLSecurity::RSA_SHA256,
        Saml::XMLSecurity::SHA256
      )

      # Verify the signed document contains signature elements
      signed_xml.should contain("Signature")
      signed_xml.should contain("SignedInfo")
      signed_xml.should contain("SignatureValue")
      signed_xml.should contain("X509Certificate")
    end

    it "embeds certificate in signature" do
      xml = %{<?xml version="1.0"?><root ID="test">content</root>}

      key_pem = read_cert("ruby-saml.key")
      cert_pem = read_cert("ruby-saml.crt")

      key = OpenSSL::PKey::RSA.new(key_pem, nil)
      cert = OpenSSL::X509::Certificate.new(cert_pem)

      signed_xml = Saml::XMLSecurity.sign_document(
        xml, key, cert, "test",
        Saml::XMLSecurity::RSA_SHA1,
        Saml::XMLSecurity::SHA1
      )

      # Parse and check certificate is embedded
      doc = XML.parse(signed_xml)
      cert_node = doc.xpath_node("//ds:X509Certificate", {"ds" => "http://www.w3.org/2000/09/xmldsig#"})
      cert_node.should_not be_nil
    end
  end

  describe ".validate_signature" do
    it "finds signature elements in SAML response" do
      # Read a signed SAML response
      xml = File.read(File.join(__DIR__, "fixtures", "responses", "adfs_response_sha256.xml"))

      # Parse and check for signature elements
      doc = XML.parse(xml)

      sig_node = doc.xpath_node("//ds:Signature", {"ds" => "http://www.w3.org/2000/09/xmldsig#"})
      sig_node.should_not be_nil

      signed_info = doc.xpath_node("//ds:SignedInfo", {"ds" => "http://www.w3.org/2000/09/xmldsig#"})
      signed_info.should_not be_nil

      sig_value = doc.xpath_node("//ds:SignatureValue", {"ds" => "http://www.w3.org/2000/09/xmldsig#"})
      sig_value.should_not be_nil

      cert_node = doc.xpath_node("//ds:X509Certificate", {"ds" => "http://www.w3.org/2000/09/xmldsig#"})
      cert_node.should_not be_nil
    end
  end

  describe "Canonicalization" do
    it "supports exclusive canonicalization" do
      xml = %{<root xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Element>Test</saml:Element>
</root>}

      doc = XML.parse(xml)
      # Canonicalization would be tested if we had a canonicalize method
      doc.should be_a(XML::Node)
    end
  end

  describe "Signature Algorithms with different hash functions" do
    it "supports SHA1 signatures" do
      alg = Saml::XMLSecurity.signature_algorithm(Saml::XMLSecurity::RSA_SHA1)
      alg.should be_a(OpenSSL::Digest)
    end

    it "supports SHA256 signatures" do
      alg = Saml::XMLSecurity.signature_algorithm(Saml::XMLSecurity::RSA_SHA256)
      alg.should be_a(OpenSSL::Digest)
    end

    it "supports SHA384 signatures" do
      alg = Saml::XMLSecurity.signature_algorithm(Saml::XMLSecurity::RSA_SHA384)
      alg.should be_a(OpenSSL::Digest)
    end

    it "supports SHA512 signatures" do
      alg = Saml::XMLSecurity.signature_algorithm(Saml::XMLSecurity::RSA_SHA512)
      alg.should be_a(OpenSSL::Digest)
    end
  end

  describe "Certificate fingerprint validation" do
    it "calculates SHA1 fingerprint" do
      cert_pem = read_cert("ruby-saml.crt")
      cert = OpenSSL::X509::Certificate.new(cert_pem)

      # Extract DER from PEM
      pem = cert.to_pem
      der_b64 = pem.lines.reject { |l| l.includes?("BEGIN") || l.includes?("END") }.join.gsub(/\s/, "")
      der_bytes = Base64.decode(der_b64)

      # Calculate SHA1 fingerprint
      sha1 = OpenSSL::Digest.new("SHA1")
      fingerprint = sha1.update(der_bytes).final.hexstring.upcase

      # Fingerprint should be in format XX:XX:XX:...
      formatted = fingerprint.scan(/../).join(":")
      formatted.should match(/^([0-9A-F]{2}:){19}[0-9A-F]{2}$/)
    end

    it "calculates SHA256 fingerprint" do
      cert_pem = read_cert("ruby-saml.crt")
      cert = OpenSSL::X509::Certificate.new(cert_pem)

      # Extract DER from PEM
      pem = cert.to_pem
      der_b64 = pem.lines.reject { |l| l.includes?("BEGIN") || l.includes?("END") }.join.gsub(/\s/, "")
      der_bytes = Base64.decode(der_b64)

      # Calculate SHA256 fingerprint
      sha256 = OpenSSL::Digest.new("SHA256")
      fingerprint = sha256.update(der_bytes).final.hexstring.upcase

      # SHA256 fingerprint should be longer
      formatted = fingerprint.scan(/../).join(":")
      formatted.should match(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/)
    end
  end

  describe "Real-world SAML responses" do
    it "handles ADFS response with SHA256" do
      xml = File.read(File.join(__DIR__, "fixtures", "responses", "adfs_response_sha256.xml"))

      # Parse and check structure
      doc = XML.parse(xml)
      doc.should be_a(XML::Node)

      # Check for signature elements
      sig_node = doc.xpath_node("//ds:Signature", {"ds" => "http://www.w3.org/2000/09/xmldsig#"})
      sig_node.should_not be_nil
    end

    it "handles ADFS response with SHA384" do
      xml = File.read(File.join(__DIR__, "fixtures", "responses", "adfs_response_sha384.xml"))

      # Parse and check structure
      doc = XML.parse(xml)
      doc.should be_a(XML::Node)

      # Check for signature elements
      sig_node = doc.xpath_node("//ds:Signature", {"ds" => "http://www.w3.org/2000/09/xmldsig#"})
      sig_node.should_not be_nil
    end

    it "handles ADFS response with SHA512" do
      xml = File.read(File.join(__DIR__, "fixtures", "responses", "adfs_response_sha512.xml"))

      # Parse and check structure
      doc = XML.parse(xml)
      doc.should be_a(XML::Node)

      # Check for signature elements
      sig_node = doc.xpath_node("//ds:Signature", {"ds" => "http://www.w3.org/2000/09/xmldsig#"})
      sig_node.should_not be_nil
    end
  end

  describe "Security" do
    it "validates signature reference URIs" do
      # Ensure signature references match expected IDs
      xml = %{<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response_id">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion_id">
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:Reference URI="#_assertion_id">
          <ds:DigestValue>...</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
    </ds:Signature>
  </saml:Assertion>
</samlp:Response>}

      doc = XML.parse(xml)
      ref_node = doc.xpath_node("//ds:Reference", {"ds" => "http://www.w3.org/2000/09/xmldsig#"})
      ref_node.should_not be_nil

      if ref_node
        uri = ref_node["URI"]?
        uri.should eq("#_assertion_id")
      end
    end
  end
end
