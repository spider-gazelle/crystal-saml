require "xml"
require "openssl"
require "base64"

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
      canonical_signed_info = canonicalize(signed_info.to_xml)

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

      # Make a copy of the referenced element and remove any signature within it
      ref_copy_xml = referenced.to_xml
      ref_doc = XML.parse(ref_copy_xml)

      # Remove signature if present (enveloped-signature transform)
      sig_node = ref_doc.xpath_node("//ds:Signature", {"ds" => DSIG})
      sig_node.try(&.unlink)

      # Canonicalize only the referenced element
      canonical = canonicalize(ref_doc.to_xml)

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
    def canonicalize(xml : String) : String
      # Crystal's XML doesn't have built-in C14N, so we do basic normalization
      # There are different modes and options that should be implemented
      doc = XML.parse(xml)
      root = doc.first_element_child
      return "" unless root

      canonicalize_node(root, nil, [] of String)
    end

    # Recursively canonicalize an XML node
    private def canonicalize_node(node : XML::Node, parent_namespaces : Hash(String, String)?, inclusive_prefixes : Array(String)) : String
      return "" unless node.element?

      # Track namespaces in scope (inherited from parent)
      current_namespaces = parent_namespaces ? parent_namespaces.dup : {} of String => String

      # Collect namespace declarations explicitly on this element
      node_namespaces = {} of String => String
      node.attributes.each do |attr|
        if attr.name == "xmlns"
          node_namespaces[""] = attr.content
        elsif attr.name.starts_with?("xmlns:")
          prefix = attr.name[6..]
          node_namespaces[prefix] = attr.content
        end
      end

      # IMPORTANT: Handle namespace from the element's namespace object
      if node.namespace
        ns = node.namespace.not_nil!
        if href = ns.href
          prefix = ns.prefix || ""
          # Only add if not already explicitly declared on this element
          unless node_namespaces.has_key?(prefix)
            node_namespaces[prefix] = href
          end
        end
      else
        # CRITICAL: If namespace is nil but element name contains ':', the namespace was lost during parsing
        # This happens when extracting an element with .to_xml() that had inherited namespaces
        # We need to infer the namespace from the known SAML/XML namespaces
        if node.name.includes?(':')
          prefix, local_name = node.name.split(':', 2)
          # Map known prefixes to their namespace URIs
          known_namespaces = {
            "ds"    => DSIG,
            "saml"  => "urn:oasis:names:tc:SAML:2.0:assertion",
            "samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
            "xsi"   => "http://www.w3.org/2001/XMLSchema-instance",
            "xs"    => "http://www.w3.org/2001/XMLSchema",
          }
          if uri = known_namespaces[prefix]?
            node_namespaces[prefix] = uri
          end
        end
      end

      # Merge node namespaces into current scope
      current_namespaces.merge!(node_namespaces)

      # Collect visibly utilized namespaces for this element
      utilized_namespaces = {} of String => String

      # Element's own namespace
      if node.namespace
        ns = node.namespace.not_nil!
        if href = ns.href
          prefix = ns.prefix || ""
          utilized_namespaces[prefix] = href
        end
      elsif node.name.includes?(':')
        # Namespace was lost - use the inferred namespace from node_namespaces
        prefix = node.name.split(':', 2)[0]
        if uri = current_namespaces[prefix]?
          utilized_namespaces[prefix] = uri
        end
      end

      # Attribute namespaces
      node.attributes.each do |attr|
        next if attr.name.starts_with?("xmlns")
        if attr.namespace
          ns = attr.namespace.not_nil!
          if href = ns.href
            prefix = ns.prefix || ""
            utilized_namespaces[prefix] = href
          end
        elsif attr.name.includes?(':')
          # Attribute namespace was also lost
          prefix = attr.name.split(':', 2)[0]
          if uri = current_namespaces[prefix]?
            utilized_namespaces[prefix] = uri
          end
        end
      end

      # Build canonical output
      result = String.build do |io|
        # Start tag
        io << "<"

        # Handle element name and prefix
        element_name = node.name
        element_prefix = ""

        if ns = node.namespace
          # Namespace object exists - use it
          element_prefix = ns.prefix || ""
          io << element_prefix << ":" if !element_prefix.empty?
          io << element_name
        elsif node.name.includes?(':')
          # Namespace was lost but prefix is in name - split it
          parts = node.name.split(':', 2)
          element_prefix = parts[0]
          element_name = parts[1]
          io << element_prefix << ":" << element_name
        else
          # No namespace
          io << element_name
        end

        # Namespace declarations (only visibly utilized, sorted)
        ns_decls = [] of {String, String}
        utilized_namespaces.each do |prefix, uri|
          # Only include if not already declared in parent or if redeclared
          if !parent_namespaces || parent_namespaces[prefix]? != uri
            ns_decls << {prefix, uri}
          end
        end

        # Sort namespace declarations: default namespace first, then by prefix
        ns_decls.sort_by! { |p, u| p.empty? ? "\x00" : p }
        ns_decls.each do |prefix, uri|
          if prefix.empty?
            io << %( xmlns=")
          else
            io << %( xmlns:#{prefix}=")
          end
          io << escape_attribute(uri)
          io << %(")
        end

        # Attributes (non-namespace, sorted)
        attrs = [] of {String, String, String}
        node.attributes.each do |attr|
          next if attr.name == "xmlns" || attr.name.starts_with?("xmlns:")

          ns_prefix = attr.namespace.try(&.prefix) || ""
          attrs << {ns_prefix, attr.name, attr.content}
        end

        # Sort attributes by namespace URI, then local name
        attrs.sort_by! do |ns_prefix, name, value|
          ns_uri = ns_prefix.empty? ? "" : (current_namespaces[ns_prefix]? || "")
          {ns_uri, name}
        end

        attrs.each do |ns_prefix, name, value|
          io << " "
          io << ns_prefix << ":" if !ns_prefix.empty?
          io << name
          io << %(=")
          io << escape_attribute(value)
          io << %(")
        end

        io << ">"

        # Child nodes
        node.children.each do |child|
          if child.element?
            io << canonicalize_node(child, current_namespaces, inclusive_prefixes)
          elsif child.text?
            # Include text nodes (excluding whitespace-only nodes)
            content = child.content
            io << escape_text(content) unless content.strip.empty?
          end
        end

        # End tag
        io << "</"
        if !element_prefix.empty?
          io << element_prefix << ":"
        end
        io << element_name
        io << ">"
      end

      result
    end

    # Escape text content for C14N
    private def escape_text(text : String) : String
      text.gsub(/[&<>\r]/) do |match|
        case match
        when "&"  then "&amp;"
        when "<"  then "&lt;"
        when ">"  then "&gt;"
        when "\r" then "&#xD;"
        else           match
        end
      end
    end

    # Escape attribute values for C14N
    private def escape_attribute(value : String) : String
      value.gsub(/[&<"\t\n\r]/) do |match|
        case match
        when "&"  then "&amp;"
        when "<"  then "&lt;"
        when "\"" then "&quot;"
        when "\t" then "&#x9;"
        when "\n" then "&#xA;"
        when "\r" then "&#xD;"
        else           match
        end
      end
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
