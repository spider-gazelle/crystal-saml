require "xml"
require "openssl"
require "openssl_ext"
require "base64"
require "uri"
require "uuid"
require "compress/zlib"

# Crystal SAML library for SAML 2.0 processing
# Converted from ruby-saml
module Saml
  {% begin %}
    VERSION = {{ `shards version "#{__DIR__}"`.chomp.stringify.downcase }}
  {% end %}
end

require "./saml/errors"
require "./saml/utils"
require "./saml/xml_security"
require "./saml/settings"
require "./saml/attributes"
require "./saml/saml_message"
require "./saml/response"
require "./saml/auth_request"
require "./saml/logout_request"
require "./saml/logout_response"
