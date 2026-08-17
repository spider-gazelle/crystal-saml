require "xml"
require "openssl"
require "base64"
require "./c14n"

module SAML
  module XMLSecurity
    extend self

    C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
    DSIG = "http://www.w3.org/2000/09/xmldsig#"

    # Signature algorithm URIs
    RSA_SHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
    RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"

    # Digest algorithm URIs
    SHA1   = "http://www.w3.org/2000/09/xmldsig#sha1"
    SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
    SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
    SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"

    ENVELOPED_SIG   = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    INC_PREFIX_LIST = "#default samlp saml ds xs xsi md"

    # Parse canonicalization algorithm URI to openssl digest type
    def canon_algorithm(algorithm : String) : String
      case algorithm
      when "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
           "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
        "c14n"
      when "http://www.w3.org/2006/12/xml-c14n11",
           "http://www.w3.org/2006/12/xml-c14n11#WithComments"
        "c14n11"
      else
        "c14n_exclusive"
      end
    end

    # Parse signature/digest algorithm URI to OpenSSL digest type
    def signature_algorithm(algorithm : String) : OpenSSL::Digest
      if algorithm =~ /(rsa-)?sha(\d+)/i
        bits = $2.to_i
        case bits
        when 256 then OpenSSL::Digest.new("SHA256")
        when 384 then OpenSSL::Digest.new("SHA384")
        when 512 then OpenSSL::Digest.new("SHA512")
        else
          OpenSSL::Digest.new("SHA1")
        end
      else
        OpenSSL::Digest.new("SHA1")
      end
    end

    # Sign an XML document
    def sign_document(xml : String, private_key : OpenSSL::PKey::RSA, certificate : OpenSSL::X509::Certificate,
                      uuid : String, signature_method : String = RSA_SHA1, digest_method : String = SHA1) : String
      doc = XML.parse(xml)

      # Create canonical form for digest calculation
      canonical = canonicalize(xml)

      # Compute digest
      digest_alg = signature_algorithm(digest_method)
      digest_value = Base64.strict_encode(digest_alg.update(canonical).final)

      # Build SignedInfo
      signed_info = build_signed_info(uuid, signature_method, digest_method, digest_value)

      # Canonicalize SignedInfo
      canonical_signed_info = canonicalize(signed_info)

      # Sign
      sig_alg = signature_algorithm(signature_method)
      signature = Base64.strict_encode(private_key.sign(sig_alg, canonical_signed_info.to_slice))

      # Build complete signature element
      signature_xml = build_signature(signed_info, signature, certificate)

      # Insert signature into document
      insert_signature(xml, signature_xml)
    end

    # Serialize a node while preserving the namespace it INHERITS from an
    # ancestor.
    #
    # `XML::Node#to_xml` serializes an element out of its document context. If
    # the element's namespace was declared on an ancestor rather than on the
    # element itself, that declaration is lost:
    #
    #   <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    #     <SignedInfo>...          =>  to_xml  =>  "<SignedInfo>..."
    #
    # The signer canonicalized `SignedInfo` in context, so its bytes carry
    # `xmlns="...xmldsig#"`. Ours did not, so the digests differed and every
    # signature verification failed.
    #
    # This only ever bit signatures that declare the XML-DSig namespace as a
    # DEFAULT namespace on `<Signature>` — which is what real IdPs emit
    # (mock-saml, Azure AD, ADFS). Signatures using a `ds:` prefix round-trip
    # correctly because libxml2 keeps prefixed declarations when serializing.
    # That is why this went unnoticed: the library was only ever verifying
    # signatures it had produced itself, and it signs with a `ds:` prefix.
    #
    # Only the element's OWN namespace is re-declared. Injecting every in-scope
    # ancestor namespace would be wrong under Exclusive C14N, which
    # deliberately omits declarations the element does not visibly utilise.
    private def serialize_in_namespace(node : XML::Node) : String
      # AS_XML without FORMAT: the default `to_xml` pretty-prints, injecting
      # indentation text nodes that were never in the signed document and
      # corrupting the canonical form.
      xml = node.to_xml(options: XML::SaveOptions::AS_XML)
      ns = node.namespace
      return xml unless ns
      href = ns.href
      return xml if href.nil? || href.empty?

      prefix = ns.prefix
      declaration = prefix ? %(xmlns:#{prefix}="#{href}") : %(xmlns="#{href}")
      tag = prefix ? "#{prefix}:#{node.name}" : node.name

      # already carried through by the serializer (prefixed case) — leave as is
      return xml if xml.starts_with?("<#{tag} #{declaration}") || xml.includes?(declaration)

      xml.sub("<#{tag}", "<#{tag} #{declaration}")
    end

    # Validate XML signature
    def validate_signature(xml : String, certificate : OpenSSL::X509::Certificate) : Bool
      doc = XML.parse(xml)

      # Find signature element
      signature = doc.xpath_node("//ds:Signature", {"ds" => DSIG})
      return false unless signature

      # Get signature value
      sig_value = signature.xpath_node(".//ds:SignatureValue", {"ds" => DSIG})
      return false unless sig_value
      signature_bytes = Base64.decode(sig_value.content.strip)

      # Get and canonicalize SignedInfo
      signed_info = signature.xpath_node(".//ds:SignedInfo", {"ds" => DSIG})
      return false unless signed_info
      canonical_signed_info = canonicalize(serialize_in_namespace(signed_info))

      # Get signature method
      sig_method = signed_info.xpath_node(".//ds:SignatureMethod", {"ds" => DSIG})
      return false unless sig_method
      sig_alg = signature_algorithm(sig_method["Algorithm"])

      # Verify signature
      return false unless certificate.public_key.verify(sig_alg, signature_bytes, canonical_signed_info.to_slice)

      # Verify digest
      verify_digest(doc, signed_info)
    end

    # Verify the digest in the signature
    private def verify_digest(doc : XML::Node, signed_info : XML::Node) : Bool
      reference = signed_info.xpath_node(".//ds:Reference", {"ds" => DSIG})
      return false unless reference

      uri = reference["URI"]?
      return false unless uri

      id = uri[1..-1] # Remove leading #

      # Find referenced element
      referenced = doc.xpath_node("//*[@ID='#{id}']")
      return false unless referenced

      # The signer's exclusive-c14n transform may carry an InclusiveNamespaces
      # PrefixList (Shibboleth signs with PrefixList="xsd"). It lives inside
      # the Signature that the enveloped transform is about to remove, so it
      # must be read from the Reference now and passed through explicitly —
      # canonicalize() cannot discover it from the signature-free document.
      inclusive_prefixes = [] of String
      if inc_ns = reference.xpath_node(".//ec:InclusiveNamespaces", {"ec" => C14N})
        if prefix_list = inc_ns["PrefixList"]?
          prefix_list.split(/\s+/).map(&.strip).reject(&.empty?).each do |pref|
            inclusive_prefixes << pref unless pref == "#default"
          end
        end
      end

      # Make a copy of the referenced element and remove any signature within
      # it. Serialize verbatim (no FORMAT) — pretty-printing would inject
      # whitespace the signer never saw.
      ref_copy_xml = referenced.to_xml(options: XML::SaveOptions::AS_XML)
      ref_doc = XML.parse(ref_copy_xml)

      # Remove signature if present (enveloped-signature transform)
      sig_node = ref_doc.xpath_node("//ds:Signature", {"ds" => DSIG})
      sig_node.try(&.unlink)

      # Canonicalize only the referenced element
      canonical = canonicalize(ref_doc.to_xml(options: XML::SaveOptions::AS_XML), inclusive_prefixes)

      # Get digest method
      digest_method = reference.xpath_node(".//ds:DigestMethod", {"ds" => DSIG})
      return false unless digest_method
      digest_alg = signature_algorithm(digest_method["Algorithm"])

      # Compute digest
      computed_digest = Base64.strict_encode(digest_alg.update(canonical).final)

      # Get expected digest
      digest_value = reference.xpath_node(".//ds:DigestValue", {"ds" => DSIG})
      return false unless digest_value
      expected_digest = digest_value.content.strip

      computed_digest == expected_digest
    end

    # Canonicalize XML using Exclusive Canonicalization (xml-exc-c14n#)
    # Implements the W3C Exclusive XML Canonicalization specification
    # https://www.w3.org/TR/xml-exc-c14n/
    def canonicalize(xml : String, inclusive_prefixes : Array(String) = [] of String) : String
      # Use our C14N 1.1 implementation with Exclusive mode
      # Parse xml to check for InclusiveNamespaces in case this is a SignedInfo
      inc_ns_prefixes = inclusive_prefixes.dup

      begin
        doc = XML.parse(xml)
        # Check if this has InclusiveNamespaces declaration
        inc_ns = doc.xpath_node("//ec:InclusiveNamespaces", {"ec" => C14N})
        if inc_ns
          if prefix_list = inc_ns["PrefixList"]?
            # Parse the prefix list (space-separated, "#default" means default namespace)
            prefixes = prefix_list.split(/\s+/).map(&.strip).reject(&.empty?)
            prefixes.each do |pref|
              inc_ns_prefixes << pref unless pref == "#default"
            end
          end
        end
      rescue
        # If parsing fails, just use provided inclusive prefixes
      end

      ::C14N.c14n(xml, exclusive: true, inclusive_prefixes: inc_ns_prefixes, with_comments: false)
    end

    # Build SignedInfo element
    private def build_signed_info(uuid : String, signature_method : String, digest_method : String, digest_value : String) : String
      String.build do |io|
        io << %(<ds:SignedInfo xmlns:ds="#{DSIG}">)
        io << %(<ds:CanonicalizationMethod Algorithm="#{C14N}"/>)
        io << %(<ds:SignatureMethod Algorithm="#{signature_method}"/>)
        io << %(<ds:Reference URI="##{uuid}">)
        io << %(<ds:Transforms>)
        io << %(<ds:Transform Algorithm="#{ENVELOPED_SIG}"/>)
        io << %(<ds:Transform Algorithm="#{C14N}">)
        io << %(<ec:InclusiveNamespaces xmlns:ec="#{C14N}" PrefixList="#{INC_PREFIX_LIST}"/>)
        io << %(</ds:Transform>)
        io << %(</ds:Transforms>)
        io << %(<ds:DigestMethod Algorithm="#{digest_method}"/>)
        io << %(<ds:DigestValue>#{digest_value}</ds:DigestValue>)
        io << %(</ds:Reference>)
        io << %(</ds:SignedInfo>)
      end
    end

    # Build complete Signature element
    private def build_signature(signed_info : String, signature : String, certificate : OpenSSL::X509::Certificate) : String
      # Convert PEM to DER format for embedding in signature
      pem = certificate.to_pem
      der_b64 = pem.lines.reject { |l| l.includes?("BEGIN") || l.includes?("END") }.join.gsub(/\s/, "")

      String.build do |io|
        io << %(<ds:Signature xmlns:ds="#{DSIG}">)
        io << signed_info
        io << %(<ds:SignatureValue>#{signature}</ds:SignatureValue>)
        io << %(<ds:KeyInfo>)
        io << %(<ds:X509Data>)
        io << %(<ds:X509Certificate>#{der_b64}</ds:X509Certificate>)
        io << %(</ds:X509Data>)
        io << %(</ds:KeyInfo>)
        io << %(</ds:Signature>)
      end
    end

    # Insert signature into XML document
    private def insert_signature(xml : String, signature_xml : String) : String
      doc = XML.parse(xml)
      root = doc.first_element_child
      return xml unless root

      # Try to insert after Issuer element
      issuer = root.xpath_node(".//saml:Issuer", {"saml" => "urn:oasis:names:tc:SAML:2.0:assertion"})

      if issuer
        # Parse signature as XML node and insert
        sig_doc = XML.parse(signature_xml)
        sig_node = sig_doc.first_element_child
        return xml unless sig_node

        # In Crystal, we need to rebuild the document with the signature inserted
        # This is a simplified approach - a full implementation would manipulate the DOM
        xml.sub("</saml:Issuer>", "</saml:Issuer>#{signature_xml}")
      else
        # Insert as first child
        root_name = root.name
        xml.sub(">", ">#{signature_xml}")
      end
    end

    # Validate that XML is safe (no DOCTYPE, etc.)
    def safe_parse(xml : String) : XML::Node
      raise ValidationError.new("Dangerous XML detected. No Doctype nodes allowed") if xml.includes?("<!DOCTYPE")

      doc = XML.parse(xml)

      # Check for internal subset (DOCTYPE)
      # Crystal's XML parser doesn't expose internal_subset, so we check the string
      raise ValidationError.new("Dangerous XML detected. No Doctype nodes allowed") if xml =~ /<!DOCTYPE/i

      doc
    end
  end
end
