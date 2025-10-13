module SAML
  # SAML2 Toolkit Settings
  class Settings
    # IdP Data
    property idp_entity_id : String?
    property idp_sso_service_url : String?
    property idp_slo_service_url : String?
    property idp_slo_response_service_url : String?
    property idp_cert : String?
    property idp_cert_fingerprint : String?
    property idp_cert_fingerprint_algorithm : String
    property idp_name_qualifier : String?

    # SP Data
    property sp_entity_id : String?
    property assertion_consumer_service_url : String?
    property assertion_consumer_service_binding : String
    property single_logout_service_url : String?
    property single_logout_service_binding : String
    property sp_name_qualifier : String?
    property name_identifier_format : String?
    property name_identifier_value : String?
    property name_identifier_value_requested : String?
    property sessionindex : String?

    # Certificate and Keys
    property certificate : String?
    property private_key : String?

    # Behavior
    property compress_request : Bool
    property compress_response : Bool
    property double_quote_xml_attribute_values : Bool
    property message_max_bytesize : Int32
    property check_malformed_doc : Bool
    property passive : Bool?
    property protocol_binding : String?
    property attributes_index : Int32?
    property force_authn : Bool?
    property soft : Bool

    # Authentication Context
    property authn_context : String | Array(String)?
    property authn_context_comparison : String?
    property authn_context_decl_ref : String | Array(String)?

    # Security settings
    property security : SecuritySettings

    def initialize
      # IdP defaults
      @idp_entity_id = nil
      @idp_sso_service_url = nil
      @idp_slo_service_url = nil
      @idp_slo_response_service_url = nil
      @idp_cert = nil
      @idp_cert_fingerprint = nil
      @idp_cert_fingerprint_algorithm = XMLSecurity::SHA1
      @idp_name_qualifier = nil

      # SP defaults
      @sp_entity_id = nil
      @assertion_consumer_service_url = nil
      @assertion_consumer_service_binding = Utils::BINDINGS[:post]
      @single_logout_service_url = nil
      @single_logout_service_binding = Utils::BINDINGS[:redirect]
      @sp_name_qualifier = nil
      @name_identifier_format = nil
      @name_identifier_value = nil
      @name_identifier_value_requested = nil
      @sessionindex = nil

      # Certificates
      @certificate = nil
      @private_key = nil

      # Behavior
      @compress_request = true
      @compress_response = true
      @double_quote_xml_attribute_values = false
      @message_max_bytesize = 250_000
      @check_malformed_doc = true
      @passive = nil
      @protocol_binding = nil
      @attributes_index = nil
      @force_authn = nil
      @soft = true

      # Authentication context
      @authn_context = nil
      @authn_context_comparison = nil
      @authn_context_decl_ref = nil

      # Security
      @security = SecuritySettings.new
    end

    # Get IdP certificate object
    def get_idp_cert : OpenSSL::X509::Certificate?
      Utils.build_cert(@idp_cert)
    end

    # Get IdP certificate fingerprint
    def get_fingerprint : String?
      return @idp_cert_fingerprint if @idp_cert_fingerprint

      if cert = get_idp_cert
        algorithm = XMLSecurity.signature_algorithm(@idp_cert_fingerprint_algorithm)
        # Convert PEM to DER for fingerprinting
        pem = cert.to_pem
        # Extract base64 content between BEGIN and END markers
        der_b64 = pem.lines.reject { |l| l.includes?("BEGIN") || l.includes?("END") }.join
        der_bytes = Base64.decode(der_b64)
        fingerprint = algorithm.update(der_bytes).final
        fingerprint.hexstring.upcase.scan(/../).join(":")
      end
    end

    # Get SP certificate object
    def get_sp_cert : OpenSSL::X509::Certificate?
      Utils.build_cert(@certificate)
    end

    # Get SP private key object
    def get_sp_key : OpenSSL::PKey::RSA?
      Utils.build_private_key(@private_key)
    end

    # Get SP signing pair (cert and key)
    def get_sp_signing_pair : Tuple(OpenSSL::X509::Certificate?, OpenSSL::PKey::RSA?)
      {get_sp_cert, get_sp_key}
    end

    # Get SP signing key
    def get_sp_signing_key : OpenSSL::PKey::RSA?
      get_sp_key
    end

    # Get SP decryption keys (for encrypted assertions)
    def get_sp_decryption_keys : Array(OpenSSL::PKey::RSA)
      keys = [] of OpenSSL::PKey::RSA
      if key = get_sp_key
        keys << key
      end
      keys
    end

    # Get IdP SSO service binding
    def idp_sso_service_binding : String
      @security.embed_sign ? Utils::BINDINGS[:post] : Utils::BINDINGS[:redirect]
    end

    # Get IdP SLO service binding
    def idp_slo_service_binding : String
      @security.embed_sign ? Utils::BINDINGS[:post] : Utils::BINDINGS[:redirect]
    end
  end

  # Security configuration settings
  struct SecuritySettings
    property authn_requests_signed : Bool
    property logout_requests_signed : Bool
    property logout_responses_signed : Bool
    property want_assertions_signed : Bool
    property want_assertions_encrypted : Bool
    property want_name_id : Bool
    property metadata_signed : Bool
    property embed_sign : Bool
    property digest_method : String
    property signature_method : String
    property check_idp_cert_expiration : Bool
    property check_sp_cert_expiration : Bool
    property strict_audience_validation : Bool
    property lowercase_url_encoding : Bool
    property want_signature_validated : Bool

    def initialize
      @authn_requests_signed = false
      @logout_requests_signed = false
      @logout_responses_signed = false
      @want_assertions_signed = false
      @want_assertions_encrypted = false
      @want_name_id = false
      @metadata_signed = false
      @embed_sign = false
      @digest_method = XMLSecurity::SHA1
      @signature_method = XMLSecurity::RSA_SHA1
      @check_idp_cert_expiration = false
      @check_sp_cert_expiration = false
      @strict_audience_validation = false
      @lowercase_url_encoding = false
      @want_signature_validated = false
    end
  end
end
