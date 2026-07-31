require "./spec_helper"

# Regression cover for signatures produced by a REAL identity provider.
#
# Every other signature spec in this suite verifies XML this library itself
# produced. `sign_document` emits `<ds:Signature>` — a PREFIXED namespace
# declaration, which libxml2 preserves when a node is serialized in isolation.
# Real IdPs (mock-saml, Azure AD, ADFS) instead declare xmldsig as the DEFAULT
# namespace on `<Signature>`, so `<SignedInfo>` INHERITS it:
#
#   <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
#     <SignedInfo> ...
#
# `XML::Node#to_xml` serializes `SignedInfo` out of document context and drops
# that inherited declaration, so the canonical bytes differed from the ones the
# IdP signed and EVERY real-world signature failed to verify. Because the suite
# only ever round-tripped this library's own output, nothing caught it.
#
# The fixture is a genuine assertion captured from https://mocksaml.com —
# RSA-SHA256, SHA-256 digest, exclusive C14N, and signatures on BOTH the
# Response and the Assertion, which is the shape real providers send.
describe SAML::XMLSecurity do
  fixture_dir = File.join(__DIR__, "fixtures", "real_idp")
  response_xml = File.read(File.join(fixture_dir, "mocksaml_response.xml"))
  certificate = OpenSSL::X509::Certificate.new(File.read(File.join(fixture_dir, "mocksaml_cert.pem")))

  describe "signatures from a real IdP" do
    it "verifies a signature whose namespace is inherited from <Signature>" do
      SAML::XMLSecurity.validate_signature(response_xml, certificate).should be_true
    end

    it "rejects the same assertion against a different certificate" do
      # sanity: the check above must be doing real cryptography, not returning
      # true for anything well-formed.
      other = OpenSSL::PKey::RSA.new(2048)
      wrong = OpenSSL::X509::Certificate.new
      wrong.public_key = other.public_key
      SAML::XMLSecurity.validate_signature(response_xml, wrong).should be_false
    end

    it "rejects the assertion once its signature value is tampered with" do
      tampered = response_xml.sub(/<SignatureValue>[^<]+<\/SignatureValue>/,
        "<SignatureValue>AAAA</SignatureValue>")
      tampered.should_not eq response_xml
      SAML::XMLSecurity.validate_signature(tampered, certificate).should be_false
    end

    it "uses the default namespace form, not a ds: prefix" do
      # guards the fixture itself: if it is ever replaced with prefixed XML
      # this file silently stops covering the regression it exists for.
      response_xml.should contain %(<Signature xmlns="http://www.w3.org/2000/09/xmldsig#")
      response_xml.should_not contain "<ds:Signature"
    end
  end
end
