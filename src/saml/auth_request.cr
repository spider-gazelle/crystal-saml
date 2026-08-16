module SAML
  # SAML2 Authentication Request (SSO SP initiated)
  class AuthRequest < SAMLMessage
    property uuid : String

    def initialize
      super()
      @uuid = Utils.uuid
    end

    # Get the request ID
    def request_id : String
      @uuid
    end

    # Create the AuthNRequest URL with SAMLRequest parameter
    def create(settings : Settings, params : Hash(String, String) = {} of String => String) : String
      request_params = create_params(settings, params)

      params_prefix = settings.idp_sso_service_url.try(&.includes?("?")) ? "&" : "?"
      saml_request = URI.encode_www_form(request_params.delete("SAMLRequest") || "")

      url = "#{settings.idp_sso_service_url}#{params_prefix}SAMLRequest=#{saml_request}"

      request_params.each do |key, value|
        url += "&#{key}=#{URI.encode_www_form(value)}"
      end

      url
    end

    # Create the parameters for the AuthNRequest
    def create_params(settings : Settings, params : Hash(String, String) = {} of String => String) : Hash(String, String)
      relay_state = params["RelayState"]?

      request_doc = create_authentication_xml_doc(settings)
      request = request_doc.to_xml

      request = deflate(request) if settings.compress_request
      base64_request = encode(request)

      request_params = {"SAMLRequest" => base64_request}

      # Sign if using redirect binding and signing is required
      sp_signing_key = settings.get_sp_signing_key
      if settings.idp_sso_service_binding == Utils::BINDINGS[:redirect] &&
         settings.security.authn_requests_signed && sp_signing_key
        sig_alg = settings.security.signature_method
        request_params["SigAlg"] = sig_alg

        query = Utils.build_query("SAMLRequest", base64_request, relay_state, sig_alg)
        sign_algorithm = XMLSecurity.signature_algorithm(sig_alg)
        signature = sp_signing_key.sign(sign_algorithm, query.to_slice)
        request_params["Signature"] = encode(String.new(signature))
      end

      # Add relay state if present
      request_params["RelayState"] = relay_state if relay_state

      # Add any other params
      params.each do |key, value|
        request_params[key] = value unless key == "RelayState"
      end

      request_params
    end

    # Create the XML document for AuthNRequest
    def create_authentication_xml_doc(settings : Settings) : XML::Node
      time = Time.utc.to_s("%Y-%m-%dT%H:%M:%SZ")

      builder = XML.build(indent: "  ") do |xml|
        # String keys: named args can't express the ':' in xmlns:samlp, and
        # an underscored attribute leaves the prefixes unbound — Shibboleth
        # (and any namespace-aware IdP) rejects the message outright.
        xml.element("samlp:AuthnRequest", {
          "xmlns:samlp"  => "urn:oasis:names:tc:SAML:2.0:protocol",
          "xmlns:saml"   => "urn:oasis:names:tc:SAML:2.0:assertion",
          "ID"           => @uuid,
          "Version"      => "2.0",
          "IssueInstant" => time,
        }) do
          # Add optional attributes
          if url = settings.idp_sso_service_url
            xml.attribute("Destination", url)
          end

          if settings.passive
            xml.attribute("IsPassive", "true")
          end

          if binding = settings.protocol_binding
            xml.attribute("ProtocolBinding", binding)
          end

          if acs_url = settings.assertion_consumer_service_url
            xml.attribute("AssertionConsumerServiceURL", acs_url)
          end

          if idx = settings.attributes_index
            xml.attribute("AttributeConsumingServiceIndex", idx.to_s)
          end

          if settings.force_authn
            xml.attribute("ForceAuthn", "true")
          end

          # Issuer
          if sp_entity_id = settings.sp_entity_id
            xml.element("saml:Issuer") { xml.text(sp_entity_id) }
          end

          # NameIDPolicy
          if name_id_format = settings.name_identifier_format
            xml.element("samlp:NameIDPolicy",
              AllowCreate: "true",
              Format: name_id_format)
          end

          # RequestedAuthnContext
          if settings.authn_context || settings.authn_context_decl_ref
            comparison = settings.authn_context_comparison || "exact"

            xml.element("samlp:RequestedAuthnContext", Comparison: comparison) do
              if authn_contexts = settings.authn_context
                contexts = authn_contexts.is_a?(Array) ? authn_contexts : [authn_contexts]
                contexts.each do |context|
                  xml.element("saml:AuthnContextClassRef") { xml.text(context) }
                end
              end

              if authn_decl_refs = settings.authn_context_decl_ref
                refs = authn_decl_refs.is_a?(Array) ? authn_decl_refs : [authn_decl_refs]
                refs.each do |ref|
                  xml.element("saml:AuthnContextDeclRef") { xml.text(ref) }
                end
              end
            end
          end
        end
      end

      # builder is already a String from XML.build
      request_xml = builder
      if settings.idp_sso_service_binding == Utils::BINDINGS[:post] &&
         settings.security.authn_requests_signed
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
