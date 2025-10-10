require "openssl"
require "base64"
require "uri"
require "uuid"

module Saml
  # Utility methods for SAML processing
  module Utils
    extend self

    BINDINGS = {
      post:     "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
      redirect: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
    }

    DSIG = "http://www.w3.org/2000/09/xmldsig#"
    XENC = "http://www.w3.org/2001/04/xmlenc#"

    # Duration format regex (ISO 8601)
    DURATION_FORMAT = /^(-?)P(?:(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:[.,]\d+)?)S)?)?|(\d+)W)$/

    UUID_PREFIX = "_"

    # Generate a SAML-compliant UUID with prefix
    def uuid : String
      UUID_PREFIX + UUID.random.to_s
    end

    # Check if a certificate is expired
    def cert_expired?(cert : OpenSSL::X509::Certificate) : Bool
      Time.utc >= cert.not_after
    end

    # Check if a certificate is active (started and not expired)
    def cert_active?(cert : OpenSSL::X509::Certificate) : Bool
      now = Time.utc
      now >= cert.not_before && now < cert.not_after
    end

    # Parse ISO 8601 duration and apply to timestamp
    def parse_duration(duration : String, timestamp : Time = Time.utc) : Time?
      matches = duration.match(DURATION_FORMAT)
      return nil unless matches

      sign = matches[1]? == "-" ? -1 : 1

      years = (matches[2]?.try(&.to_i) || 0) * sign
      months = (matches[3]?.try(&.to_i) || 0) * sign
      days = (matches[4]?.try(&.to_i) || 0) * sign
      hours = (matches[5]?.try(&.to_i) || 0) * sign
      minutes = (matches[6]?.try(&.to_i) || 0) * sign
      seconds = (matches[7]?.try(&.to_f) || 0.0) * sign
      weeks = (matches[8]?.try(&.to_i) || 0) * sign

      result = timestamp
      result = result.shift(years: years) if years != 0
      result = result.shift(months: months) if months != 0
      result = result.shift(days: days + (weeks * 7)) if days != 0 || weeks != 0
      result = result.shift(hours: hours) if hours != 0
      result = result.shift(minutes: minutes) if minutes != 0
      result = result.shift(seconds: seconds.to_i) if seconds != 0

      result
    end

    # Format a certificate properly with BEGIN/END markers
    def format_cert(cert : String) : String
      return cert if cert.empty?
      return cert unless cert.ascii_only?

      # Handle multiple certificates
      if cert.scan(/BEGIN CERTIFICATE/).size > 1
        certs = [] of String
        cert.scan(/-{5}BEGIN CERTIFICATE-{5}[\n\r]?.*?-{5}END CERTIFICATE-{5}[\n\r]?/m) do |match|
          certs << format_cert(match[0])
        end
        return certs.join("\n")
      end

      # Remove existing markers and whitespace
      formatted = cert.gsub(/\-{5}\s?(BEGIN|END) CERTIFICATE\s?\-{5}/, "")
      formatted = formatted.gsub(/[\r\n\s]/, "")

      # Split into 64-character lines
      lines = [] of String
      formatted.chars.in_groups_of(64, ' ').each do |group|
        line = String.build { |io| group.each { |c| io << c if c } }
        lines << line unless line.strip.empty?
      end

      "-----BEGIN CERTIFICATE-----\n#{lines.join("\n")}\n-----END CERTIFICATE-----"
    end

    # Format a private key properly with BEGIN/END markers
    def format_private_key(key : String) : String
      return key if key.empty?
      return key if key.includes?("\x0d")

      # Check if it's an RSA key
      rsa_key = key.includes?("RSA PRIVATE KEY")

      # Remove existing markers and whitespace
      formatted = key.gsub(/\-{5}\s?(BEGIN|END)( RSA)? PRIVATE KEY\s?\-{5}/, "")
      formatted = formatted.gsub(/[\r\n\s]/, "")

      # Split into 64-character lines
      lines = [] of String
      formatted.chars.in_groups_of(64, ' ').each do |group|
        line = String.build { |io| group.each { |c| io << c if c } }
        lines << line unless line.strip.empty?
      end

      key_label = rsa_key ? "RSA PRIVATE KEY" : "PRIVATE KEY"
      "-----BEGIN #{key_label}-----\n#{lines.join("\n")}\n-----END #{key_label}-----"
    end

    # Build OpenSSL certificate object from string
    def build_cert(cert : String?) : OpenSSL::X509::Certificate?
      return nil if cert.nil? || cert.empty?
      pem = format_cert(cert)
      OpenSSL::X509::Certificate.new(pem)
    end

    # Build OpenSSL private key object from string
    def build_private_key(key : String?) : OpenSSL::PKey::RSA?
      return nil if key.nil? || key.empty?
      pem = format_private_key(key)
      OpenSSL::PKey::RSA.new(pem, nil)
    end

    # Build query string for HTTP-Redirect binding
    def build_query(type : String, data : String, relay_state : String?, sig_alg : String) : String
      query = "#{type}=#{URI.encode_www_form(data)}"
      query += "&RelayState=#{URI.encode_www_form(relay_state)}" if relay_state
      query += "&SigAlg=#{URI.encode_www_form(sig_alg)}"
      query
    end

    # Build query string from raw (already encoded) parts
    def build_query_from_raw(type : String, raw_data : String, raw_relay_state : String?, raw_sig_alg : String) : String
      query = "#{type}=#{raw_data}"
      query += "&RelayState=#{raw_relay_state}" if raw_relay_state
      query += "&SigAlg=#{raw_sig_alg}"
      query
    end

    # Verify signature on HTTP-Redirect binding
    def verify_signature(cert : OpenSSL::X509::Certificate, sig_alg : String, signature : String, query_string : String) : Bool
      algorithm = XMLSecurity.signature_algorithm(sig_alg)
      signature_data = Base64.decode(signature)
      cert.public_key.verify(algorithm, signature_data, query_string.to_slice)
    end

    # Build status error message
    def status_error_msg(error_msg : String, raw_status_code : String?, status_message : String?) : String
      msg = error_msg.dup

      if raw_status_code
        if raw_status_code.includes?("|")
          codes = raw_status_code.split(" | ").map { |code| code.split(':').last }
          msg += ", was #{codes.join(" => ")}"
        else
          msg += ", was #{raw_status_code.split(':').last}"
        end
      end

      msg += " -> #{status_message}" if status_message

      msg
    end

    # Decrypt encrypted data using multiple private keys
    def decrypt_multi(encrypted_node : XML::Node, private_keys : Array(OpenSSL::PKey::RSA)) : String
      raise ArgumentError.new("private_keys must be specified") if private_keys.empty?

      error : Exception? = nil
      private_keys.each do |key|
        begin
          return decrypt_data(encrypted_node, key)
        rescue ex : OpenSSL::Error
          error = ex
        end
      end

      raise error if error
      raise Error.new("Failed to decrypt with any provided key")
    end

    # Decrypt encrypted data
    def decrypt_data(encrypted_node : XML::Node, private_key : OpenSSL::PKey::RSA) : String
      encrypt_data = encrypted_node.xpath_node("./xenc:EncryptedData",
        {"xenc" => XENC})
      raise Error.new("EncryptedData element not found") unless encrypt_data

      symmetric_key = retrieve_symmetric_key(encrypt_data, private_key)

      cipher_value = encrypt_data.xpath_node("./xenc:CipherData/xenc:CipherValue",
        {"xenc" => XENC})
      raise Error.new("CipherValue not found") unless cipher_value

      node = Base64.decode_string(cipher_value.content)

      encrypt_method = encrypt_data.xpath_node("./xenc:EncryptionMethod",
        {"xenc" => XENC})
      raise Error.new("EncryptionMethod not found") unless encrypt_method

      algorithm = encrypt_method["Algorithm"]
      retrieve_plaintext(node, symmetric_key, algorithm)
    end

    # Retrieve symmetric key from encrypted data
    def retrieve_symmetric_key(encrypt_data : XML::Node, private_key : OpenSSL::PKey::RSA) : Bytes
      encrypted_key = encrypt_data.xpath_node(
        "./ds:KeyInfo/xenc:EncryptedKey | ./KeyInfo/xenc:EncryptedKey",
        {"ds" => DSIG, "xenc" => XENC})
      raise Error.new("EncryptedKey not found") unless encrypted_key

      cipher_value = encrypted_key.xpath_node("./xenc:CipherData/xenc:CipherValue",
        {"xenc" => XENC})
      raise Error.new("CipherValue not found") unless cipher_value

      cipher_text = Base64.decode(cipher_value.content)

      encrypt_method = encrypted_key.xpath_node("./xenc:EncryptionMethod",
        {"xenc" => XENC})
      raise Error.new("EncryptionMethod not found") unless encrypt_method

      algorithm = encrypt_method["Algorithm"]
      retrieve_plaintext(cipher_text, private_key, algorithm)
    end

    # Decrypt cipher text based on algorithm
    def retrieve_plaintext(cipher_text : Bytes | String, key : Bytes | OpenSSL::PKey::RSA, algorithm : String) : String
      cipher_bytes = cipher_text.is_a?(String) ? cipher_text.to_slice : cipher_text

      case algorithm
      when "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
        decrypt_with_cipher("DES-EDE3-CBC", cipher_bytes, key.as(Bytes))
      when "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
        decrypt_with_cipher("AES-128-CBC", cipher_bytes, key.as(Bytes))
      when "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
        decrypt_with_cipher("AES-192-CBC", cipher_bytes, key.as(Bytes))
      when "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
        decrypt_with_cipher("AES-256-CBC", cipher_bytes, key.as(Bytes))
      when "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
        key.as(OpenSSL::PKey::RSA).private_decrypt(cipher_bytes)
      when "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
        key.as(OpenSSL::PKey::RSA).private_decrypt(cipher_bytes, OpenSSL::Padding::PKCS1_OAEP)
      else
        String.new(cipher_bytes)
      end
    end

    # Decrypt with OpenSSL cipher
    private def decrypt_with_cipher(cipher_name : String, cipher_text : Bytes, key : Bytes) : String
      cipher = OpenSSL::Cipher.new(cipher_name)
      cipher.decrypt

      iv_len = cipher.iv_len
      data = cipher_text[iv_len..-1]
      cipher.key = key
      cipher.iv = cipher_text[0...iv_len]
      cipher.padding = false

      io = IO::Memory.new
      io.write(cipher.update(data))
      io.write(cipher.final)
      io.to_s
    end

    # Match URIs with case-insensitive comparison
    def uri_match?(url1 : String, url2 : String) : Bool
      uri1 = URI.parse(url1)
      uri2 = URI.parse(url2)

      return false if uri1.scheme.nil? || uri2.scheme.nil?
      return false if uri1.host.nil? || uri2.host.nil?

      uri1.scheme.try(&.downcase) == uri2.scheme.try(&.downcase) &&
        uri1.host.try(&.downcase) == uri2.host.try(&.downcase) &&
        uri1.path == uri2.path &&
        uri1.query == uri2.query
    rescue URI::Error
      url1 == url2
    end
  end
end
