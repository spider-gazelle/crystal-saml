module Saml
  # SAML2 Logout Response
  class LogoutResponse < SamlMessage
    property uuid : String

    getter document : XML::Node
    getter response_string : String
    getter settings : Settings
    getter options : Hash(Symbol, String)?

    @status_code : String?

    def initialize(response : String, @settings : Settings, @options = nil)
      super()
      @uuid = Utils.uuid
      @soft = settings.soft
      @response_string = decode_raw_saml(response, settings)
      @document = XML.parse(@response_string)
    end

    # Alternate constructor for creating a LogoutResponse
    def self.create(settings : Settings, request_id : String? = nil, logout_message : String? = nil, params : Hash(String, String) = {} of String => String) : String
      response = new_from_builder(settings, request_id, logout_message)
      response.create(settings, params)
    end

    # Create a new LogoutResponse for sending
    def self.new_from_builder(settings : Settings, request_id : String? = nil, logout_message : String? = nil) : LogoutResponse
      response_string = build_logout_response_xml(settings, request_id, logout_message)
      new(Base64.strict_encode(response_string), settings)
    end

    # Build the logout response XML
    private def self.build_logout_response_xml(settings : Settings, request_id : String?, logout_message : String?) : String
      time = Time.utc.to_s("%Y-%m-%dT%H:%M:%SZ")
      response_id = Utils.uuid

      builder = XML.build(indent: "  ") do |xml|
        xml.element("samlp:LogoutResponse",
          xmlns_samlp: "urn:oasis:names:tc:SAML:2.0:protocol",
          xmlns_saml: "urn:oasis:names:tc:SAML:2.0:assertion",
          ID: response_id,
          Version: "2.0",
          IssueInstant: time) do
          # Add InResponseTo if we have a request ID
          xml.attribute("InResponseTo", request_id) if request_id

          # Add destination
          if url = settings.idp_slo_response_service_url || settings.idp_slo_service_url
            xml.attribute("Destination", url)
          end

          # Issuer
          if sp_entity_id = settings.sp_entity_id
            xml.element("saml:Issuer") { xml.text(sp_entity_id) }
          end

          # Status
          xml.element("samlp:Status") do
            xml.element("samlp:StatusCode", Value: "urn:oasis:names:tc:SAML:2.0:status:Success")

            if logout_message
              xml.element("samlp:StatusMessage") { xml.text(logout_message) }
            end
          end
        end
      end

      response_xml = builder.to_xml

      # Sign if required
      if settings.security.logout_responses_signed
        cert = settings.get_sp_cert
        key = settings.get_sp_key

        if cert && key
          response_xml = XMLSecurity.sign_document(
            response_xml, key, cert, response_id,
            settings.security.signature_method,
            settings.security.digest_method
          )
        end
      end

      response_xml
    end

    # Create the URL with SAMLResponse parameter
    def create(settings : Settings, params : Hash(String, String) = {} of String => String) : String
      response_params = create_params(settings, params)

      params_prefix = settings.idp_slo_response_service_url.try(&.includes?("?")) ? "&" : "?"
      saml_response = URI.encode_www_form(response_params.delete("SAMLResponse") || "")

      url = "#{settings.idp_slo_response_service_url}#{params_prefix}SAMLResponse=#{saml_response}"

      response_params.each do |key, value|
        url += "&#{key}=#{URI.encode_www_form(value)}"
      end

      url
    end

    # Create params for the logout response
    def create_params(settings : Settings, params : Hash(String, String) = {} of String => String) : Hash(String, String)
      relay_state = params["RelayState"]?

      response = @response_string
      response = deflate(response) if settings.compress_response
      base64_response = encode(response)

      response_params = {"SAMLResponse" => base64_response}
      response_params["RelayState"] = relay_state if relay_state

      params.each do |key, value|
        response_params[key] = value unless key == "RelayState"
      end

      response_params
    end

    # Validate the logout response
    def valid? : Bool
      validate
    end

    # Check if status is success
    def success? : Bool
      status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
    end

    # Get status code
    def status_code : String?
      @status_code ||= begin
        node = @document.xpath_node("/p:LogoutResponse/p:Status/p:StatusCode",
          {"p" => PROTOCOL})
        node.try(&.["Value"]?)
      end
    end

    # Get status message
    def status_message : String?
      node = @document.xpath_node("/p:LogoutResponse/p:Status/p:StatusMessage",
        {"p" => PROTOCOL})
      node.try(&.content.presence)
    end

    # Get InResponseTo
    def in_response_to : String?
      node = @document.xpath_node("/p:LogoutResponse", {"p" => PROTOCOL})
      node.try(&.["InResponseTo"]?)
    end

    # Get issuer
    def issuer : String?
      node = @document.xpath_node("/p:LogoutResponse/a:Issuer",
        {"p" => PROTOCOL, "a" => ASSERTION})
      node.try(&.content.presence)
    end

    private def validate : Bool
      reset_errors!

      validations = [
        :validate_version,
        :validate_id,
        :validate_success_status,
        :validate_issuer,
      ]

      validations.all? { |validation| send(validation) }
    end

    private def validate_version : Bool
      unless version(@document) == "2.0"
        return append_error("Unsupported SAML version")
      end
      true
    end

    private def validate_id : Bool
      unless id(@document)
        return append_error("Missing ID attribute on LogoutResponse")
      end
      true
    end

    private def validate_success_status : Bool
      return true if success?

      error_msg = "The status code of the LogoutResponse was not Success"
      status_error = Utils.status_error_msg(error_msg, status_code, status_message)
      append_error(status_error)
    end

    private def validate_issuer : Bool
      return true if settings.idp_entity_id.nil?

      iss = issuer
      return append_error("No issuer in LogoutResponse") unless iss

      unless Utils.uri_match?(iss, settings.idp_entity_id.not_nil!)
        return append_error("Issuer mismatch")
      end

      true
    end
  end
end
