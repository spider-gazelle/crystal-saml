# Crystal SAML

A Crystal lang library for SAML 2.0 processing.

## Features

- **SAML 2.0 Support**: Complete implementation of SAML 2.0 protocol
- **Authentication Requests**: Create and process AuthNRequests (SSO)
- **SAML Responses**: Validate and extract data from SAML responses
- **Single Logout (SLO)**: Support for logout requests and responses
- **XML Security**: XML signing and signature validation
- **Encryption**: Support for encrypted assertions
- **Flexible Configuration**: Comprehensive settings for IdP and SP configuration

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  crystal-saml:
    github: spider-gazelle/crystal-saml
```

## Usage

### Basic Configuration

```crystal
require "crystal-saml"

settings = SAML::Settings.new
settings.idp_sso_service_url = "https://idp.example.com/sso"
settings.idp_entity_id = "https://idp.example.com"
settings.idp_cert_fingerprint = "AA:BB:CC:DD:EE:FF:..."
settings.sp_entity_id = "https://sp.example.com"
settings.assertion_consumer_service_url = "https://sp.example.com/saml/acs"
```

### Creating an AuthN Request

```crystal
request = SAML::AuthRequest.new
url = request.create(settings)
# Redirect user to: url
```

### Processing a SAML Response

```crystal
response = SAML::Response.new(params["SAMLResponse"], settings)

if response.valid?
  user_id = response.name_id
  attributes = response.attributes
  session_index = response.sessionindex

  # Log user in
else
  puts "Errors: #{response.errors}"
end
```

### Creating a Logout Request

```crystal
settings.name_identifier_value = current_user.email
settings.sessionindex = current_user.session_index

logout_request = SAML::LogoutRequest.new
url = logout_request.create(settings)
# Redirect user to: url
```

### Security Settings

```crystal
settings.security.authn_requests_signed = true
settings.security.logout_requests_signed = true
settings.security.want_assertions_signed = true
settings.security.digest_method = SAML::XMLSecurity::SHA256
settings.security.signature_method = SAML::XMLSecurity::RSA_SHA256
```

## Architecture

The library is organized into the following modules:

- **SAML::Utils**: Utility functions for certificates, UUIDs, encryption, etc.
- **SAML::XMLSecurity**: XML signing and validation
- **SAML::Settings**: Configuration management
- **SAML::Attributes**: Attribute handling from SAML responses
- **SAML::SAMLMessage**: Base class for SAML messages with encoding/decoding
- **SAML::Response**: SAML response processing and validation
- **SAML::AuthRequest**: AuthN request generation
- **SAML::LogoutRequest/LogoutResponse**: SLO support

## Testing

```bash
crystal spec
```

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## License

MIT License - see LICENSE file for details

## Credits

Converted from [ruby-saml](https://github.com/SAML-Toolkits/ruby-saml) by OneLogin.
