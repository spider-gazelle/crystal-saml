require "./spec_helper"

# Signature shapes produced by Apache Santuario (Shibboleth IdP, Okta):
# newline text nodes between SignedInfo children are part of the signed
# canonical bytes, and the exclusive-c14n transform carries an
# InclusiveNamespaces PrefixList that must be honoured when computing the
# reference digest.

private DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
private EXC_NS  = "http://www.w3.org/2001/10/xml-exc-c14n#"
private ENV_SIG = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
private RSA256  = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
private SHA256U = "http://www.w3.org/2001/04/xmlenc#sha256"

private def test_key_and_cert
  key = OpenSSL::PKey::RSA.new(2048)
  cert = OpenSSL::X509::Certificate.new
  cert.public_key = key.public_key
  {key, cert}
end

private def response_skeleton(resp_id : String, signature_block : String) : String
  %(<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="#{resp_id}" Version="2.0"><saml:Issuer>https://idp.example.org/idp/shibboleth</saml:Issuer>#{signature_block}<saml:Assertion ID="_a1" Version="2.0"><saml:Issuer>https://idp.example.org/idp/shibboleth</saml:Issuer><saml:Subject><saml:NameID>someone</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>)
end

# Shibboleth output shape: xsd/xsi declared on the AttributeValue, xsd
# utilised only inside the xsi:type attribute VALUE, PrefixList="xsd"
private def shibboleth_skeleton(resp_id : String, signature_block : String) : String
  %(<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="#{resp_id}" Version="2.0"><saml:Issuer>https://idp.example.org/idp/shibboleth</saml:Issuer>#{signature_block}<saml:Assertion ID="_a1" Version="2.0"><saml:AttributeStatement><saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6"><saml:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">joe@example.edu</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>)
end

private def signed_info_xml(resp_id : String, digest : String) : String
  %(<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="#{EXC_NS}"/><ds:SignatureMethod Algorithm="#{RSA256}"/><ds:Reference URI="##{resp_id}"><ds:Transforms><ds:Transform Algorithm="#{ENV_SIG}"/><ds:Transform Algorithm="#{EXC_NS}"/></ds:Transforms><ds:DigestMethod Algorithm="#{SHA256U}"/><ds:DigestValue>#{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>)
end

private def signed_info_with_prefix_list(resp_id : String, digest : String) : String
  %(<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="#{EXC_NS}"/><ds:SignatureMethod Algorithm="#{RSA256}"/><ds:Reference URI="##{resp_id}"><ds:Transforms><ds:Transform Algorithm="#{ENV_SIG}"/><ds:Transform Algorithm="#{EXC_NS}"><ec:InclusiveNamespaces xmlns:ec="#{EXC_NS}" PrefixList="xsd"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="#{SHA256U}"/><ds:DigestValue>#{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>)
end

private def signature_block(signed_info : String, sig_value : String) : String
  %(<ds:Signature xmlns:ds="#{DSIG_NS}">#{signed_info}<ds:SignatureValue>#{sig_value}</ds:SignatureValue></ds:Signature>)
end

# The digest the signer computes over the signature-free document
private def reference_digest(sig_free_skeleton : String, inclusive_prefixes : Array(String) = [] of String) : String
  canonical = SAML::XMLSecurity.canonicalize(sig_free_skeleton, inclusive_prefixes)
  Base64.strict_encode(OpenSSL::Digest.new("SHA256").update(canonical).final)
end

# Hand-derive the canonical bytes a spec-compliant exclusive C14N emits for a
# SignedInfo that carries whitespace text nodes: declare the inherited
# xmlns:ds on the root, keep every text node verbatim, expand empty-element
# tags. Deliberately NOT computed through the library under test.
private def expected_canonical(signed_info : String) : String
  declaration = %(xmlns:ds="#{DSIG_NS}")
  with_decl = signed_info.includes?(declaration) ? signed_info : signed_info.sub("<ds:SignedInfo", "<ds:SignedInfo #{declaration}")
  with_decl.gsub(%r{<((?:ds|ec):[\w-]+)([^>]*?)/>}) { "<#{$1}#{$2}></#{$1}>" }
end

describe "Santuario-shaped signatures" do
  describe "whitespace-only text nodes in SignedInfo" do
    it "verifies a signature computed over newline-bearing SignedInfo bytes" do
      key, cert = test_key_and_cert
      resp_id = "_ws_a"
      digest = reference_digest(response_skeleton(resp_id, ""))

      # Santuario shape: newline text nodes between every tag of SignedInfo,
      # signature computed over the canonical form THAT KEEPS those newlines
      si_newlines = signed_info_xml(resp_id, digest).gsub("><", ">\n<")
      santuario_canonical = expected_canonical(si_newlines)

      sig = Base64.strict_encode(key.sign(OpenSSL::Digest.new("SHA256"), santuario_canonical.to_slice))
      doc = response_skeleton(resp_id, signature_block(si_newlines, sig))

      SAML::XMLSecurity.validate_signature(doc, cert).should be_true
    end

    it "still verifies a compact (self-generated shape) signature" do
      key, cert = test_key_and_cert
      resp_id = "_ws_b"
      digest = reference_digest(response_skeleton(resp_id, ""))

      si_compact = signed_info_xml(resp_id, digest)
      compact_canonical = expected_canonical(si_compact)

      sig = Base64.strict_encode(key.sign(OpenSSL::Digest.new("SHA256"), compact_canonical.to_slice))
      doc = response_skeleton(resp_id, signature_block(si_compact, sig))

      SAML::XMLSecurity.validate_signature(doc, cert).should be_true
    end

    it "rejects a newline-bearing SignedInfo whose signature covers the compact bytes" do
      key, cert = test_key_and_cert
      resp_id = "_ws_c"
      digest = reference_digest(response_skeleton(resp_id, ""))

      si_compact = signed_info_xml(resp_id, digest)
      si_newlines = si_compact.gsub("><", ">\n<")
      compact_canonical = expected_canonical(si_compact)

      sig = Base64.strict_encode(key.sign(OpenSSL::Digest.new("SHA256"), compact_canonical.to_slice))
      doc = response_skeleton(resp_id, signature_block(si_newlines, sig))

      SAML::XMLSecurity.validate_signature(doc, cert).should be_false
    end
  end

  describe "InclusiveNamespaces PrefixList in the reference transform" do
    it "honours the PrefixList when computing the reference digest" do
      key, cert = test_key_and_cert
      resp_id = "_pl_a"

      # digest as the signer computes it: PrefixList "xsd" honoured
      no_sig = shibboleth_skeleton(resp_id, "")
      signer_canonical = SAML::XMLSecurity.canonicalize(no_sig, ["xsd"])
      ignored_canonical = SAML::XMLSecurity.canonicalize(no_sig)
      # the PrefixList must change the canonical form, or this test proves nothing
      signer_canonical.should_not eq ignored_canonical

      digest = Base64.strict_encode(OpenSSL::Digest.new("SHA256").update(signer_canonical).final)
      si = signed_info_with_prefix_list(resp_id, digest)
      si_canonical = expected_canonical(si)
      sig = Base64.strict_encode(key.sign(OpenSSL::Digest.new("SHA256"), si_canonical.to_slice))

      doc = shibboleth_skeleton(resp_id, signature_block(si, sig))
      SAML::XMLSecurity.validate_signature(doc, cert).should be_true
    end
  end
end

describe "allowed clock drift" do
  it "defaults to 10 seconds at the settings level (legacy Ruby service parity)" do
    SAML::Settings.new.allowed_clock_drift.should eq 10.seconds
  end

  it "falls back from response options to the settings value" do
    settings = SAML::Settings.new
    settings.allowed_clock_drift = 25.seconds

    response = SAML::Response.new("<xml/>", settings)
    response.allowed_clock_drift.should eq 25.seconds

    options = Hash(Symbol, String | Bool | Int32 | Float64).new
    options[:allowed_clock_drift] = 3
    with_option = SAML::Response.new("<xml/>", settings, options)
    with_option.allowed_clock_drift.should eq 3.seconds
  end
end
