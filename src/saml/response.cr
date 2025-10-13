module SAML
  # SAML2 Authentication Response
  class Response < SAMLMessage
    DSIG = "http://www.w3.org/2000/09/xmldsig#"
    XENC = "http://www.w3.org/2001/04/xmlenc#"

    getter document : XML::Node
    getter response_string : String
    getter settings : Settings
    getter options : Hash(Symbol, String | Bool | Int32 | Float64)?

    @attributes : Attributes?
    @name_id : String?
    @sessionindex : String?
    @status_code : String?

    def initialize(response : String, @settings : Settings, @options = nil)
      super()
      @soft = settings.soft
      @response_string = decode_raw_saml(response, settings)
      @document = XML.parse(@response_string)
    end

    # Validate the SAML Response
    def valid?(collect_errors : Bool = false) : Bool
      validate(collect_errors)
    end

    # Get NameID from response
    def name_id : String?
      @name_id ||= begin
        node = name_id_node
        node.try(&.content.presence)
      end
    end

    # Get NameID format
    def name_id_format : String?
      node = name_id_node
      node.try(&.["Format"]?)
    end

    # Get session index from AuthnStatement
    def sessionindex : String?
      @sessionindex ||= begin
        node = xpath_first_from_signed_assertion("a:AuthnStatement")
        node.try(&.["SessionIndex"]?)
      end
    end

    # Get attributes from AttributeStatement
    def attributes : Attributes
      @attributes ||= begin
        attrs = Attributes.new

        stmt_elements = xpath_from_signed_assertion("a:AttributeStatement")
        stmt_elements.each do |stmt_element|
          stmt_element.children.select(&.element?).each do |attr_element|
            next unless attr_element.name == "Attribute" || attr_element.name == "EncryptedAttribute"

            name = attr_element["Name"]?
            next unless name

            values = attr_element.children.select { |e| e.name == "AttributeValue" }.map do |e|
              # Check for nil attribute
              nil_attr = e["xsi:nil"]?
              if nil_attr && (nil_attr == "true" || nil_attr == "1")
                nil
              else
                e.content.presence
              end
            end

            attrs.add(name, values)
          end
        end

        attrs
      end
    end

    # Get session expiration time
    def session_expires_at : Time?
      node = xpath_first_from_signed_assertion("a:AuthnStatement")
      parse_time(node, "SessionNotOnOrAfter")
    end

    # Check if status is success
    def success? : Bool
      status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
    end

    # Get status code
    def status_code : String?
      @status_code ||= begin
        nodes = @document.xpath_nodes("/p:Response/p:Status/p:StatusCode",
          {"p" => PROTOCOL})

        if nodes.size == 1
          node = nodes[0]
          code = node["Value"]?

          unless code == "urn:oasis:names:tc:SAML:2.0:status:Success"
            # Check for nested status codes
            inner_nodes = @document.xpath_nodes("/p:Response/p:Status/p:StatusCode/p:StatusCode",
              {"p" => PROTOCOL})
            statuses = inner_nodes.map { |n| n["Value"]? }.compact
            code = ([code] + statuses).join(" | ") unless statuses.empty?
          end

          code
        end
      end
    end

    # Get status message
    def status_message : String?
      nodes = @document.xpath_nodes("/p:Response/p:Status/p:StatusMessage",
        {"p" => PROTOCOL})
      nodes.first?.try(&.content.presence) if nodes.size == 1
    end

    # Get InResponseTo attribute
    def in_response_to : String?
      node = @document.xpath_node("/p:Response", {"p" => PROTOCOL})
      node.try(&.["InResponseTo"]?)
    end

    # Get Destination attribute
    def destination : String?
      node = @document.xpath_node("/p:Response", {"p" => PROTOCOL})
      node.try(&.["Destination"]?)
    end

    # Get audiences
    def audiences : Array(String)
      nodes = xpath_from_signed_assertion("a:Conditions/a:AudienceRestriction/a:Audience")
      nodes.map { |node| node.content }.reject(&.empty?)
    end

    # Get issuers
    def issuers : Array(String)
      response_nodes = @document.xpath_nodes("/p:Response/a:Issuer",
        {"p" => PROTOCOL, "a" => ASSERTION}).to_a

      assertion_nodes = xpath_from_signed_assertion("a:Issuer")

      (response_nodes + assertion_nodes).map { |node| node.content }.compact.uniq
    end

    # Get NotBefore condition
    def not_before : Time?
      conditions = xpath_first_from_signed_assertion("a:Conditions")
      parse_time(conditions, "NotBefore")
    end

    # Get NotOnOrAfter condition
    def not_on_or_after : Time?
      conditions = xpath_first_from_signed_assertion("a:Conditions")
      parse_time(conditions, "NotOnOrAfter")
    end

    # Allowed clock drift for time validation
    def allowed_clock_drift : Time::Span
      drift = options.try(&.[]?(:allowed_clock_drift))
      if drift.is_a?(Number)
        Time::Span.new(seconds: drift.to_f.abs.to_i)
      else
        Time::Span.zero
      end
    end

    private def validate(collect_errors : Bool) : Bool
      reset_errors!

      if collect_errors
        validate_version
        validate_id
        validate_success_status
        validate_conditions
        validate_audience
        validate_destination
        validate_issuer
        validate_signature
        @errors.empty?
      else
        validate_version &&
          validate_id &&
          validate_success_status &&
          validate_conditions &&
          validate_audience &&
          validate_destination &&
          validate_issuer &&
          validate_signature
      end
    end

    private def validate_version : Bool
      unless version(@document) == "2.0"
        return append_error("Unsupported SAML version")
      end
      true
    end

    private def validate_id : Bool
      unless id(@document)
        return append_error("Missing ID attribute on SAML Response")
      end
      true
    end

    private def validate_success_status : Bool
      return true if success?

      error_msg = "The status code of the Response was not Success"
      status_error = Utils.status_error_msg(error_msg, status_code, status_message)
      append_error(status_error)
    end

    private def validate_conditions : Bool
      now = Time.utc
      drift = allowed_clock_drift

      if nb = not_before
        if now < (nb - drift)
          return append_error("Current time is earlier than NotBefore condition")
        end
      end

      if nooa = not_on_or_after
        if now >= (nooa + drift)
          return append_error("Current time is on or after NotOnOrAfter condition")
        end
      end

      true
    end

    private def validate_audience : Bool
      return true if options.try(&.[]?(:skip_audience)) == true
      return true if settings.sp_entity_id.nil?

      auds = audiences
      return true if auds.empty? && !settings.security.strict_audience_validation

      unless auds.includes?(settings.sp_entity_id.not_nil!)
        return append_error("Invalid Audience. Expected #{settings.sp_entity_id}")
      end

      true
    end

    private def validate_destination : Bool
      dest = destination
      return true if dest.nil?
      return true if options.try(&.[]?(:skip_destination)) == true

      acs_url = settings.assertion_consumer_service_url
      return true if acs_url.nil?

      unless Utils.uri_match?(dest, acs_url)
        return append_error("Response received at wrong destination")
      end

      true
    end

    private def validate_issuer : Bool
      return true if settings.idp_entity_id.nil?

      iss = issuers
      iss.each do |issuer|
        unless Utils.uri_match?(issuer, settings.idp_entity_id.not_nil!)
          return append_error("Issuer mismatch. Expected #{settings.idp_entity_id}")
        end
      end

      true
    end

    private def validate_signature : Bool
      # Find signature in response or assertion
      sig_node = @document.xpath_node("//ds:Signature", {"ds" => DSIG})
      return true unless sig_node # No signature to validate

      # Try to get explicit certificate from settings
      cert = settings.get_idp_cert

      # If no explicit cert, try to extract from XML and validate fingerprint
      if cert.nil?
        if fingerprint = settings.idp_cert_fingerprint
          # Extract certificate from XML signature
          extracted_cert = Utils.extract_cert_from_signature(@document)
          return append_error("No certificate in SAML response and no IdP certificate configured") unless extracted_cert

          # Compute fingerprint of extracted certificate
          computed_fingerprint = Utils.compute_fingerprint(extracted_cert, settings.idp_cert_fingerprint_algorithm)

          # Normalize fingerprints for comparison (remove colons, convert to uppercase)
          normalized_expected = fingerprint.gsub(":", "").upcase
          normalized_computed = computed_fingerprint.gsub(":", "").upcase

          # Validate fingerprint matches
          unless normalized_computed == normalized_expected
            return append_error("Certificate fingerprint mismatch")
          end

          # Use extracted certificate for further validation
          cert = extracted_cert
        else
          return append_error("No IdP certificate or fingerprint configured")
        end
      end

      # Only validate XML signature if explicitly requested
      # Fingerprint validation above is the primary security mechanism
      if settings.security.want_signature_validated
        # Validate signature using XML canonicalization
        unless XMLSecurity.validate_signature(@document.to_xml, cert)
          return append_error("Invalid signature")
        end
      end

      # Check cert expiration if configured
      if settings.security.check_idp_cert_expiration
        if Utils.cert_expired?(cert)
          return append_error("IdP certificate expired")
        end
      end

      true
    end

    private def name_id_node : XML::Node?
      xpath_first_from_signed_assertion("a:Subject/a:NameID")
    end

    private def xpath_first_from_signed_assertion(path : String) : XML::Node?
      # Get the assertion element
      assertion = @document.xpath_node("//a:Assertion", {"a" => ASSERTION})
      return nil unless assertion

      assertion.xpath_node(path, {"a" => ASSERTION})
    end

    private def xpath_from_signed_assertion(path : String) : Array(XML::Node)
      assertion = @document.xpath_node("//a:Assertion", {"a" => ASSERTION})
      return [] of XML::Node unless assertion

      assertion.xpath_nodes(path, {"a" => ASSERTION}).to_a
    end

    private def parse_time(node : XML::Node?, attribute : String) : Time?
      return nil unless node
      attr = node[attribute]?
      return nil unless attr

      Time.parse_rfc3339(attr)
    rescue Time::Format::Error
      nil
    end
  end
end
