module Saml
  # Base SAML error
  class Error < Exception
  end

  # Raised when SAML validation fails
  class ValidationError < Error
  end

  # Raised when SAML settings are invalid
  class SettingError < Error
  end

  # Raised when HTTP requests fail
  class HttpError < Error
    getter :code

    def initialize(message : String, @code : Int32? = nil)
      super(message)
    end
  end
end
