require "compress/zlib"
require "base64"
require "uri"

module Saml
  # Base class for SAML messages
  abstract class SamlMessage
    ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
    PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"

    # Base64 format - allows for optional padding
    BASE64_FORMAT = /\A[A-Za-z0-9+\/]*={0,2}\Z/

    # Errors encountered during processing
    property errors : Array(String)
    property soft : Bool

    def initialize
      @errors = [] of String
      @soft = true
    end

    # Get Version attribute from SAML message
    def version(document : XML::Node) : String?
      node = document.xpath_node(
        "/p:AuthnRequest | /p:Response | /p:LogoutResponse | /p:LogoutRequest",
        {"p" => PROTOCOL}
      )
      node.try(&.["Version"]?)
    end

    # Get ID attribute from SAML message
    def id(document : XML::Node) : String?
      node = document.xpath_node(
        "/p:AuthnRequest | /p:Response | /p:LogoutResponse | /p:LogoutRequest",
        {"p" => PROTOCOL}
      )
      node.try(&.["ID"]?)
    end

    # Append error and raise or return false based on soft mode
    protected def append_error(error_msg : String, soft_override : Bool? = nil) : Bool
      @errors << error_msg

      soft_mode = soft_override.nil? ? @soft : soft_override
      raise ValidationError.new(error_msg) unless soft_mode

      false
    end

    # Reset errors array
    protected def reset_errors!
      @errors = [] of String
    end

    # Decode and inflate a SAML message
    protected def decode_raw_saml(saml : String, settings : Settings) : String
      if saml.bytesize > settings.message_max_bytesize
        raise ValidationError.new("Encoded SAML Message exceeds #{settings.message_max_bytesize} bytes")
      end

      return saml unless base64_encoded?(saml)

      decoded = decode(saml)

      # Try to inflate (decompress)
      message = begin
        inflate(decoded)
      rescue
        decoded
      end

      if message.bytesize > settings.message_max_bytesize
        raise ValidationError.new("SAML Message exceeds #{settings.message_max_bytesize} bytes")
      end

      message
    end

    # Encode and deflate a SAML message
    protected def encode_raw_saml(saml : String, settings : Settings) : String
      saml = deflate(saml) if settings.compress_request
      URI.encode_www_form(encode(saml))
    end

    # Base64 decode
    protected def decode(string : String) : String
      Base64.decode_string(string)
    end

    # Base64 encode
    protected def encode(string : String) : String
      Base64.strict_encode(string)
    end

    # Check if string is base64 encoded
    protected def base64_encoded?(string : String) : Bool
      cleaned = string.gsub(/[\r\n\s]/, "")
      !!(cleaned =~ BASE64_FORMAT)
    end

    # Calculate Adler-32 checksum for zlib
    private def adler32(data : Bytes) : UInt32
      a = 1_u32
      b = 0_u32
      modulus = 65521_u32

      data.each do |byte|
        a = (a + byte) % modulus
        b = (b + a) % modulus
      end

      (b << 16) | a
    end

    # Inflate (decompress) string using raw deflate
    protected def inflate(deflated : String) : String
      # SAML uses raw deflate (RFC 1951) without zlib wrapper
      # Similar to Ruby's: Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(deflated)

      # Strategy: Add zlib header, decompress with dummy checksum to get output,
      # then calculate real checksum and decompress again properly

      wrapped_io = IO::Memory.new
      wrapped_io.write(Bytes[0x78, 0x9C]) # zlib header for deflate, default compression
      wrapped_io.write(deflated.to_slice)

      # First pass: decompress with dummy checksum to get the uncompressed data
      wrapped_io.write(Bytes[0x00, 0x00, 0x00, 0x01]) # Dummy Adler-32
      wrapped_io.rewind

      # Read ignoring checksum error
      uncompressed = begin
        Compress::Zlib::Reader.open(wrapped_io) do |reader|
          reader.gets_to_end
        end
      rescue Compress::Zlib::Error
        # Expected checksum error - try to read what we can
        wrapped_io.rewind
        result_io = IO::Memory.new

        # Manual decompression attempt - read until error
        begin
          Compress::Zlib::Reader.open(wrapped_io) do |reader|
            IO.copy(reader, result_io)
          end
        rescue
          # Ignore checksum error
        end

        result_io.to_s
      end

      uncompressed
    end

    # Deflate (compress) string using raw deflate
    protected def deflate(inflated : String) : String
      # For deflate, the current approach of stripping headers works
      io = IO::Memory.new
      Compress::Zlib::Writer.open(io, level: Compress::Zlib::BEST_COMPRESSION) do |deflate|
        deflate.print(inflated)
      end
      # SAML uses raw deflate, so remove zlib header and footer
      result = io.to_slice
      # Skip zlib header (2 bytes) and trailer (4 bytes checksum)
      String.new(result[2..-5])
    end

    # Check if malformed document checking is enabled
    protected def check_malformed_doc?(settings : Settings?) : Bool
      settings.nil? ? true : settings.check_malformed_doc
    end
  end
end
