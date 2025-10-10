module Saml
  # SAML2 Logout Request (SLO SP initiated)
  class LogoutRequest < SamlMessage
    property uuid : String

    def initialize
      super()
      @uuid = Utils.uuid
    end

    # Get the request ID
    def request_id : String
      @uuid
    end

    # Create the LogoutRequest URL with SAMLRequest parameter
    def create(settings : Settings, params : Hash(String, String) = {} of String => String) : String
      request_params = create_params(settings, params)

      params_prefix = settings.idp_slo_service_url.try(&.includes?("?")) ? "&" : "?"
      saml_request = URI.encode_www_form(request_params.delete("SAMLRequest") || "")

      url = "#{settings.idp_slo_service_url}#{params_prefix}SAMLRequest=#{saml_request}"

      request_params.each do |key, value|
        url += "&#{key}=#{URI.encode_www_form(value)}"
      end

      url
    end

    # Create the parameters for the LogoutRequest
    def create_params(settings : Settings, params : Hash(String, String) = {} of String => String) : Hash(String, String)
      relay_state = params["RelayState"]?

      request_doc = create_logout_request_xml_doc(settings)
      request = request_doc.to_xml

      request = deflate(request) if settings.compress_request
      base64_request = encode(request)

      request_params = {"SAMLRequest" => base64_request}

      # Sign if using redirect binding
      sp_signing_key = settings.get_sp_signing_key
      if settings.idp_slo_service_binding == Utils::BINDINGS[:redirect] &&
         settings.security.logout_requests_signed && sp_signing_key
        sig_alg = settings.security.signature_method
        request_params["SigAlg"] = sig_alg

        query = Utils.build_query("SAMLRequest", base64_request, relay_state, sig_alg)
        sign_algorithm = XMLSecurity.signature_algorithm(sig_alg)
        signature = sp_signing_key.sign(sign_algorithm, query.to_slice)
        request_params["Signature"] = encode(String.new(signature))
      end

      request_params["RelayState"] = relay_state if relay_state

      params.each do |key, value|
        request_params[key] = value unless key == "RelayState"
      end

      request_params
    end

    # Create the XML document for LogoutRequest
    def create_logout_request_xml_doc(settings : Settings) : XML::Node
      time = Time.utc.to_s("%Y-%m-%dT%H:%M:%SZ")

      builder = XML.build(indent: "  ") do |xml|
        xml.element("samlp:LogoutRequest",
          xmlns_samlp: "urn:oasis:names:tc:SAML:2.0:protocol",
          xmlns_saml: "urn:oasis:names:tc:SAML:2.0:assertion",
          ID: @uuid,
          Version: "2.0",
          IssueInstant: time) do
          # Add destination if available
          if url = settings.idp_slo_service_url
            xml.attribute("Destination", url)
          end

          # Issuer
          if sp_entity_id = settings.sp_entity_id
            xml.element("saml:Issuer") { xml.text(sp_entity_id) }
          end

          # NameID
          xml.element("saml:NameID") do
            if name_id = settings.name_identifier_value
              if qualifier = settings.idp_name_qualifier
                xml.attribute("NameQualifier", qualifier)
              end

              if sp_qualifier = settings.sp_name_qualifier
                xml.attribute("SPNameQualifier", sp_qualifier)
              end

              if format = settings.name_identifier_format
                xml.attribute("Format", format)
              end

              xml.text(name_id)
            else
              # Generate transient NameID if none provided
              xml.attribute("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient")
              xml.text(Utils.uuid)
            end
          end

          # SessionIndex (if available)
          if session_index = settings.sessionindex
            xml.element("samlp:SessionIndex") { xml.text(session_index) }
          end
        end
      end

      # Sign if using POST binding
      request_xml = builder.to_xml
      if settings.idp_slo_service_binding == Utils::BINDINGS[:post] &&
         settings.security.logout_requests_signed
        cert = settings.get_sp_cert
        key = settings.get_sp_key

        if cert && key
          request_xml = XMLSecurity.sign_document(
            request_xml, key, cert, @uuid,
            settings.security.signature_method,
            settings.security.digest_method
          )
        end
      end

      XML.parse(request_xml)
    end
  end
end
